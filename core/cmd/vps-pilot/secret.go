package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/primus-oem/vps-pilot/core/internal/secrets"
	"github.com/primus-oem/vps-pilot/core/internal/state"
	sshtransport "github.com/primus-oem/vps-pilot/core/internal/transport/ssh"
	"golang.org/x/term"
)

func runSecretCommand(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: vps-pilot secret <list|bind|rotate|revoke>")
	}
	store, err := state.OpenDefault(ctx)
	if err != nil {
		return err
	}
	defer store.Close()

	switch args[0] {
	case "list":
		return listSecretBindings(ctx, store, args[1:])
	case "bind", "rotate":
		return provisionSecret(ctx, store, args[0], args[1:])
	case "revoke":
		return revokeSecret(ctx, store, args[1:])
	default:
		return fmt.Errorf("unknown secret command %q", args[0])
	}
}

func listSecretBindings(ctx context.Context, store *state.Store, args []string) error {
	fs := flag.NewFlagSet("secret list", flag.ContinueOnError)
	applicationID := fs.String("application", "", "application ID")
	environment := fs.String("environment", "", "environment")
	if err := fs.Parse(args); err != nil {
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
}

func provisionSecret(ctx context.Context, store *state.Store, operation string, args []string) error {
	fs := flag.NewFlagSet("secret "+operation, flag.ContinueOnError)
	applicationID := fs.String("application", "", "application ID")
	environment := fs.String("environment", "", "environment")
	hostAlias := fs.String("host", "", "SSH host alias")
	service := fs.String("service", "", "Compose service name")
	name := fs.String("name", "", "secret name")
	version := fs.String("version", "", "secret version")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *applicationID == "" || *environment == "" || *hostAlias == "" || *service == "" || *name == "" {
		return fmt.Errorf("secret %s requires -application -environment -host -service -name", operation)
	}
	if *version == "" {
		*version = "v1"
	}
	if err := requireTerminal(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Enter secret %s (input is hidden): ", *name)
	value, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return fmt.Errorf("read secret value: %w", err)
	}
	if len(value) == 0 {
		clear(value)
		return errors.New("secret value is required")
	}
	host, err := store.GetHost(ctx, *hostAlias)
	if err != nil {
		clear(value)
		return err
	}
	manager := sshtransport.NewManager()
	defer manager.Close()
	receipt, err := secrets.NewSSHBroker(manager).Provision(ctx, host, secrets.ProvisionRequest{
		Project: *applicationID, Environment: *environment, Service: *service,
		Name: *name, Version: *version,
	}, value)
	if err != nil {
		return err
	}
	binding := state.SecretBinding{
		Application: *applicationID, Environment: *environment, Host: *hostAlias,
		Service: *service, Name: *name, Reference: receipt.Digest,
		Version: *version, Status: "present",
	}
	if err := store.UpsertSecretBinding(ctx, binding); err != nil {
		return err
	}
	fmt.Printf("secret binding recorded as metadata only: %s/%s %s=%s\n",
		*applicationID, *environment, *name, *version)
	return nil
}

func revokeSecret(ctx context.Context, store *state.Store, args []string) error {
	if len(args) != 5 {
		return errors.New("usage: vps-pilot secret revoke <application> <environment> <host> <service> <name>")
	}
	binding, err := store.GetSecretBinding(ctx, args[0], args[1], args[2], args[3], args[4])
	if err != nil {
		return err
	}
	host, err := store.GetHost(ctx, binding.Host)
	if err != nil {
		return err
	}
	request := secrets.ProvisionRequest{
		Project: binding.Application, Environment: binding.Environment,
		Service: binding.Service, Name: binding.Name, Version: binding.Version,
	}
	targetPath, err := request.TargetPath()
	if err != nil {
		return err
	}
	manager := sshtransport.NewManager()
	defer manager.Close()
	if err := secrets.NewSSHBroker(manager).Revoke(ctx, host, secrets.ProvisionReceipt{TargetPath: targetPath}); err != nil {
		return err
	}
	if err := store.RevokeSecretBinding(ctx, args[0], args[1], args[2], args[3], args[4]); err != nil {
		return err
	}
	fmt.Println("secret binding revoked")
	return nil
}

func requireTerminal() error {
	info, err := os.Stdin.Stat()
	if err != nil {
		return fmt.Errorf("inspect secret intake terminal: %w", err)
	}
	if info.Mode()&os.ModeCharDevice == 0 {
		return errors.New("secret intake requires a trusted interactive terminal")
	}
	return nil
}
