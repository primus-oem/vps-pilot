package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/primus-oem/vps-pilot/core/internal/application"
	"github.com/primus-oem/vps-pilot/core/internal/inventory"
	"github.com/primus-oem/vps-pilot/core/internal/mcpserver"
	"github.com/primus-oem/vps-pilot/core/internal/state"
	sshtransport "github.com/primus-oem/vps-pilot/core/internal/transport/ssh"
)

var version = "0.1.0-dev"

func main() {
	if len(os.Args) < 2 {
		fail("usage: vps-pilot <mcp|host|app|version>")
	}
	ctx := context.Background()
	switch os.Args[1] {
	case "app":
		if err := runAppCommand(ctx, os.Args[2:]); err != nil {
			fail(err.Error())
		}
	case "host":
		if err := runHostCommand(ctx, os.Args[2:]); err != nil {
			fail(err.Error())
		}
	case "mcp":
		store, err := state.OpenDefault(ctx)
		if err != nil {
			fail(err.Error())
		}
		defer store.Close()
		if err := mcpserver.Run(ctx, version, store); err != nil {
			fail(err.Error())
		}
	case "version":
		fmt.Println(version)
	default:
		fail("unknown command")
	}
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(2)
}

func runHostCommand(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: vps-pilot host <list|add|test|health>")
	}
	store, err := state.OpenDefault(ctx)
	if err != nil {
		return err
	}
	defer store.Close()

	switch args[0] {
	case "list":
		hosts, err := store.ListHosts(ctx)
		if err != nil {
			return err
		}
		for _, host := range hosts {
			fmt.Printf("%s\t%s\t%s@%s:%d\n", host.ID, host.Environment, host.User, host.Host, host.Port)
		}
		return nil
	case "add":
		fs := flag.NewFlagSet("host add", flag.ContinueOnError)
		alias := fs.String("alias", "", "SSH alias")
		environment := fs.String("environment", "staging", "host environment")
		hostName := fs.String("host", "", "SSH host name")
		user := fs.String("user", "", "SSH user")
		port := fs.Int("port", 22, "SSH port")
		identity := fs.String("identity", "", "private key or identity file")
		knownHosts := fs.String("known-hosts", "~/.ssh/known_hosts", "known_hosts file")
		timeout := fs.Int("timeout", 10, "connection timeout seconds")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if strings.TrimSpace(*alias) == "" {
			return fmt.Errorf("host add requires -alias")
		}
		resolved, err := sshtransport.ResolveAlias(*alias)
		if err == nil {
			if strings.TrimSpace(*hostName) == "" {
				*hostName = resolved.Host
			}
			if strings.TrimSpace(*user) == "" {
				*user = resolved.User
			}
			if *port == 22 && resolved.Port != 0 {
				*port = resolved.Port
			}
			if strings.TrimSpace(*identity) == "" && len(resolved.IdentityFiles) > 0 {
				*identity = resolved.IdentityFiles[0]
			}
		}
		if strings.TrimSpace(*hostName) == "" || strings.TrimSpace(*user) == "" {
			return fmt.Errorf("host add requires -host and -user")
		}
		host := state.Host{Environment: *environment, SSHAlias: *alias, Host: *hostName, Port: *port, User: *user, IdentityFile: *identity, KnownHostsFile: *knownHosts, TimeoutSeconds: *timeout}
		if err := store.UpsertHost(ctx, host); err != nil {
			return err
		}
		fmt.Printf("configured host %s\n", *alias)
		return nil
	case "test", "health":
		fs := flag.NewFlagSet("host "+args[0], flag.ContinueOnError)
		alias := fs.String("alias", "", "SSH alias")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		host, err := store.GetHost(ctx, *alias)
		if err != nil {
			return err
		}
		manager := sshtransport.NewManager()
		defer manager.Close()
		healthCtx, cancel := inventory.ContextWithDeadline(ctx, time.Duration(host.TimeoutSeconds)*time.Second)
		defer cancel()
		client, err := manager.Connect(healthCtx, sshtransport.Config{
			Alias: host.SSHAlias, Host: host.Host, User: host.User, Port: host.Port,
			IdentityFiles: []string{host.IdentityFile}, KnownHostsFile: host.KnownHostsFile,
			Timeout: time.Duration(host.TimeoutSeconds) * time.Second,
		})
		if err != nil {
			return err
		}
		if args[0] == "test" {
			fmt.Printf("SSH connection ok: %s\n", host.SSHAlias)
			return nil
		}
		health, err := inventory.Collect(healthCtx, client)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(health)
	default:
		return fmt.Errorf("unknown host command %q", args[0])
	}
}

func runAppCommand(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: vps-pilot app <validate|import|list|graph>")
	}
	store, err := state.OpenDefault(ctx)
	if err != nil {
		return err
	}
	defer store.Close()

	switch args[0] {
	case "plan":
		if len(args) != 4 {
			return fmt.Errorf("usage: vps-pilot app plan <application-id> <environment> <service,service>")
		}
		app, err := store.GetApplication(ctx, args[1])
		if err != nil {
			return err
		}
		var manifest application.Manifest
		if err := json.Unmarshal([]byte(app.Manifest), &manifest); err != nil {
			return err
		}
		services := strings.Split(args[3], ",")
		plan, err := application.CreateReleasePlan(&manifest, args[2], services)
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(plan)
	case "validate":
		if len(args) != 2 {
			return fmt.Errorf("usage: vps-pilot app validate <manifest.yaml>")
		}
		data, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}
		manifest, err := application.Parse(data)
		if err != nil {
			return err
		}
		order, err := application.TopologicalOrder(manifest)
		if err != nil {
			return err
		}
		fmt.Printf("valid: %s (%d services)\n", manifest.Metadata.Name, len(order))
		return nil
	case "import":
		if len(args) != 2 {
			return fmt.Errorf("usage: vps-pilot app import <manifest.yaml>")
		}
		data, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}
		manifest, err := application.Parse(data)
		if err != nil {
			return err
		}
		canonical, err := json.Marshal(manifest)
		if err != nil {
			return err
		}
		digest := fmt.Sprintf("sha256:%x", sha256.Sum256(canonical))
		app := state.Application{ID: manifest.Metadata.Name, Name: manifest.Metadata.Name, Digest: digest, Manifest: string(canonical)}
		if err := store.SaveApplication(ctx, app); err != nil {
			return err
		}
		fmt.Printf("imported %s %s\n", app.Name, app.Digest)
		return nil
	case "list":
		apps, err := store.ListApplications(ctx)
		if err != nil {
			return err
		}
		for _, app := range apps {
			fmt.Printf("%s\t%s\n", app.ID, app.Digest)
		}
		return nil
	case "graph":
		if len(args) != 2 {
			return fmt.Errorf("usage: vps-pilot app graph <application-id>")
		}
		app, err := store.GetApplication(ctx, args[1])
		if err != nil {
			return err
		}
		var manifest application.Manifest
		if err := json.Unmarshal([]byte(app.Manifest), &manifest); err != nil {
			return err
		}
		order, err := application.TopologicalOrder(&manifest)
		if err != nil {
			return err
		}
		for _, name := range order {
			service := manifest.Services[name]
			fmt.Printf("%s\t%s\t%s/%s\n", name, service.Role, service.Deploy.Project, service.Deploy.Service)
		}
		return nil
	default:
		return fmt.Errorf("unknown app command %q", args[0])
	}
}
