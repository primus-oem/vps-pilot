package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/primus-oem/vps-pilot/core/internal/inventory"
	"github.com/primus-oem/vps-pilot/core/internal/state"
	sshtransport "github.com/primus-oem/vps-pilot/core/internal/transport/ssh"
)

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
		return addHost(ctx, store, args[1:])
	case "test", "health":
		return inspectHost(ctx, store, args[0], args[1:])
	default:
		return fmt.Errorf("unknown host command %q", args[0])
	}
}

func addHost(ctx context.Context, store *state.Store, args []string) error {
	fs := flag.NewFlagSet("host add", flag.ContinueOnError)
	alias := fs.String("alias", "", "SSH alias")
	environment := fs.String("environment", "staging", "host environment")
	hostName := fs.String("host", "", "SSH host name")
	user := fs.String("user", "", "SSH user")
	port := fs.Int("port", 22, "SSH port")
	identity := fs.String("identity", "", "private key or identity file")
	knownHosts := fs.String("known-hosts", "~/.ssh/known_hosts", "known_hosts file")
	timeout := fs.Int("timeout", 10, "connection timeout seconds")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*alias) == "" {
		return fmt.Errorf("host add requires -alias")
	}
	resolved, err := sshtransport.ResolveAlias(*alias)
	if err == nil {
		applySSHDefaults(resolved, hostName, user, port, identity)
	}
	if strings.TrimSpace(*hostName) == "" || strings.TrimSpace(*user) == "" {
		return fmt.Errorf("host add requires -host and -user")
	}
	return store.UpsertHost(ctx, state.Host{
		Environment: *environment, SSHAlias: *alias, Host: *hostName,
		Port: *port, User: *user, IdentityFile: *identity,
		KnownHostsFile: *knownHosts, TimeoutSeconds: *timeout,
	})
}

func applySSHDefaults(resolved sshtransport.Config, host, user *string, port *int, identity *string) {
	if strings.TrimSpace(*host) == "" {
		*host = resolved.Host
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

func inspectHost(ctx context.Context, store *state.Store, operation string, args []string) error {
	fs := flag.NewFlagSet("host "+operation, flag.ContinueOnError)
	alias := fs.String("alias", "", "SSH alias")
	if err := fs.Parse(args); err != nil {
		return err
	}
	host, err := store.GetHost(ctx, *alias)
	if err != nil {
		return err
	}
	manager := sshtransport.NewManager()
	defer manager.Close()
	hostCtx, cancel := inventory.ContextWithDeadline(ctx, time.Duration(host.TimeoutSeconds)*time.Second)
	defer cancel()
	client, err := manager.Connect(hostCtx, sshtransport.Config{
		Alias: host.SSHAlias, Host: host.Host, User: host.User, Port: host.Port,
		IdentityFiles: []string{host.IdentityFile}, KnownHostsFile: host.KnownHostsFile,
		Timeout: time.Duration(host.TimeoutSeconds) * time.Second,
	})
	if err != nil {
		return err
	}
	if operation == "test" {
		fmt.Printf("SSH connection ok: %s\n", host.SSHAlias)
		return nil
	}
	health, err := inventory.Collect(hostCtx, client)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(health)
}
