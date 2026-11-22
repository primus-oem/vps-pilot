package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/user"
	"strings"
	"time"

	"github.com/primus-oem/vps-pilot/core/internal/application"
	"github.com/primus-oem/vps-pilot/core/internal/approval"
	"github.com/primus-oem/vps-pilot/core/internal/deployment"
	"github.com/primus-oem/vps-pilot/core/internal/inventory"
	"github.com/primus-oem/vps-pilot/core/internal/mcpserver"
	"github.com/primus-oem/vps-pilot/core/internal/planning"
	"github.com/primus-oem/vps-pilot/core/internal/state"
	sshtransport "github.com/primus-oem/vps-pilot/core/internal/transport/ssh"
)

var version = "0.1.0-dev"

func main() {
	if len(os.Args) < 2 {
		fail("usage: vps-pilot <mcp|host|app|secret|version>")
	}
	ctx := context.Background()
	switch os.Args[1] {
	case "app":
		if err := runAppCommand(ctx, os.Args[2:]); err != nil {
			fail(err.Error())
		}
	case "secret":
		if err := runSecretCommand(ctx, os.Args[2:]); err != nil {
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

func runSecretCommand(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: vps-pilot secret <list|bind|rotate|revoke>")
	}
	store, err := state.OpenDefault(ctx)
	if err != nil {
		return err
	}
	defer store.Close()
	switch args[0] {
	case "list":
		fs := flag.NewFlagSet("secret list", flag.ContinueOnError)
		applicationID := fs.String("application", "", "application ID")
		environment := fs.String("environment", "", "environment")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		bindings, err := store.ListSecretBindings(ctx, *applicationID, *environment)
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		output := make([]map[string]string, 0, len(bindings))
		for _, binding := range bindings {
			output = append(output, map[string]string{
				"application": binding.Application, "environment": binding.Environment,
				"host": binding.Host, "service": binding.Service, "name": binding.Name,
				"reference_digest": binding.Reference, "version": binding.Version, "status": binding.Status,
			})
		}
		return encoder.Encode(output)
	case "bind", "rotate":
		fs := flag.NewFlagSet("secret "+args[0], flag.ContinueOnError)
		applicationID := fs.String("application", "", "application ID")
		environment := fs.String("environment", "", "environment")
		host := fs.String("host", "", "SSH host alias")
		service := fs.String("service", "", "Compose service name")
		name := fs.String("name", "", "secret name")
		reference := fs.String("reference", "", "opaque secret reference")
		version := fs.String("version", "", "secret version")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *applicationID == "" || *environment == "" || *host == "" || *service == "" || *name == "" || *reference == "" {
			return fmt.Errorf("secret %s requires -application -environment -host -service -name -reference", args[0])
		}
		if *version == "" {
			*version = "v1"
		}
		referenceDigest := sha256.Sum256([]byte(*reference))
		binding := state.SecretBinding{
			Application: *applicationID, Environment: *environment, Host: *host,
			Service: *service, Name: *name,
			Reference: fmt.Sprintf("sha256:%x", referenceDigest), Version: *version, Status: "present",
		}
		if err := store.UpsertSecretBinding(ctx, binding); err != nil {
			return err
		}
		fmt.Printf("secret binding recorded as metadata only: %s/%s %s=%s\n", *applicationID, *environment, *name, *version)
		return nil
	case "revoke":
		if len(args) != 6 {
			return fmt.Errorf("usage: vps-pilot secret revoke <application> <environment> <host> <service> <name>")
		}
		if err := store.RevokeSecretBinding(ctx, args[1], args[2], args[3], args[4], args[5]); err != nil {
			return err
		}
		fmt.Println("secret binding revoked")
		return nil
	default:
		return fmt.Errorf("unknown secret command %q", args[0])
	}
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
		return fmt.Errorf("usage: vps-pilot app <validate|import|list|graph|inventory|plan|preflight|approve|deploy>")
	}
	store, err := state.OpenDefault(ctx)
	if err != nil {
		return err
	}
	defer store.Close()

	switch args[0] {
	case "preflight", "deploy":
		if len(args) != 2 {
			return fmt.Errorf("usage: vps-pilot app %s <plan-digest>", args[0])
		}
		actor, err := user.Current()
		if err != nil {
			return fmt.Errorf("resolve local operation actor: %w", err)
		}
		manager := sshtransport.NewManager()
		defer manager.Close()
		executor := deployment.NewExecutor(store, deployment.NewSSHRemote(manager))
		if args[0] == "preflight" {
			plan, err := executor.Preflight(ctx, args[1], actor.Username)
			if err != nil {
				return err
			}
			encoder := json.NewEncoder(os.Stdout)
			encoder.SetIndent("", "  ")
			return encoder.Encode(plan)
		}
		result, executeErr := executor.Execute(ctx, args[1], actor.Username)
		if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
			return err
		}
		return executeErr
	case "approve":
		if len(args) != 2 {
			return fmt.Errorf("usage: vps-pilot app approve <plan-digest>")
		}
		info, err := os.Stdin.Stat()
		if err != nil {
			return fmt.Errorf("inspect approval input: %w", err)
		}
		if info.Mode()&os.ModeCharDevice == 0 {
			return fmt.Errorf("approval requires a trusted interactive terminal")
		}
		snapshot, err := store.GetReleasePlan(ctx, args[1])
		if err != nil {
			return err
		}
		var plan application.ReleasePlan
		if err := json.Unmarshal([]byte(snapshot.PlanJSON), &plan); err != nil {
			return fmt.Errorf("decode stored release plan: %w", err)
		}
		if plan.Digest != args[1] || !application.HasValidDigest(plan) {
			return fmt.Errorf("stored release plan failed integrity validation")
		}
		preview, err := json.MarshalIndent(struct {
			Application string                         `json:"application"`
			Environment string                         `json:"environment"`
			Digest      string                         `json:"digest"`
			Selected    []string                       `json:"selected_services"`
			Targets     []application.ReleaseTarget    `json:"targets"`
			Services    []application.ReleaseService   `json:"services"`
			Preflight   []application.ComposePreflight `json:"preflight"`
			Risk        application.RiskSummary        `json:"risk"`
			Diff        application.ReleaseDiff        `json:"diff"`
		}{plan.Application, plan.Environment, plan.Digest, plan.Selected, plan.Targets, plan.Services, plan.Preflight, plan.Risk, plan.Diff}, "", "  ")
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, string(preview))
		shortDigest := strings.TrimPrefix(plan.Digest, "sha256:")[:12]
		fmt.Fprintf(os.Stderr, "Type APPROVE %s to authorize this exact plan: ", shortDigest)
		confirmation, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			return fmt.Errorf("read approval confirmation: %w", err)
		}
		if strings.TrimSpace(confirmation) != "APPROVE "+shortDigest {
			return fmt.Errorf("approval confirmation did not match")
		}
		actor, err := user.Current()
		if err != nil {
			return fmt.Errorf("resolve local approval actor: %w", err)
		}
		if err := approval.ApprovePlan(ctx, store, plan.Digest, actor.Username); err != nil {
			return err
		}
		fmt.Fprintln(os.Stdout, "plan approved locally; approval expires in 5 minutes")
		return nil
	case "plan":
		if len(args) != 4 {
			return fmt.Errorf("usage: vps-pilot app plan <application-id> <environment> <service,service>")
		}
		services := strings.Split(args[3], ",")
		plan, err := planning.New(store).Create(ctx, args[1], args[2], services)
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
	case "inventory":
		if len(args) != 2 {
			return fmt.Errorf("usage: vps-pilot app inventory <application-id>")
		}
		app, err := store.GetApplication(ctx, args[1])
		if err != nil {
			return err
		}
		var manifest application.Manifest
		if err := json.Unmarshal([]byte(app.Manifest), &manifest); err != nil {
			return err
		}
		inventory, err := application.BuildInventory(&manifest, app.Digest)
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(inventory)
	default:
		return fmt.Errorf("unknown app command %q", args[0])
	}
}
