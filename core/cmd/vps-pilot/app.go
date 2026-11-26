package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"strings"

	"github.com/primus-oem/vps-pilot/core/internal/application"
	"github.com/primus-oem/vps-pilot/core/internal/approval"
	"github.com/primus-oem/vps-pilot/core/internal/deployment"
	"github.com/primus-oem/vps-pilot/core/internal/planning"
	"github.com/primus-oem/vps-pilot/core/internal/state"
	sshtransport "github.com/primus-oem/vps-pilot/core/internal/transport/ssh"
)

func runAppCommand(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: vps-pilot app <validate|import|list|graph|inventory|plan|preflight|approve|deploy|reconcile>")
	}
	store, err := state.OpenDefault(ctx)
	if err != nil {
		return err
	}
	defer store.Close()

	switch args[0] {
	case "reconcile":
		return reconcilePlan(ctx, store, args[1:])
	case "preflight", "deploy":
		return runPlanOperation(ctx, store, args[0], args[1:])
	case "approve":
		return approvePlan(ctx, store, args[1:])
	case "plan":
		return planRelease(ctx, store, args[1:])
	case "validate":
		return validateManifest(args[1:])
	case "import":
		return importManifest(ctx, store, args[1:])
	case "list":
		return listApplications(ctx, store)
	case "graph":
		return printApplicationGraph(ctx, store, args[1:])
	case "inventory":
		return printApplicationInventory(ctx, store, args[1:])
	default:
		return fmt.Errorf("unknown app command %q", args[0])
	}
}

func reconcilePlan(ctx context.Context, store *state.Store, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: vps-pilot app reconcile <plan-digest>")
	}
	actor, err := user.Current()
	if err != nil {
		return fmt.Errorf("resolve local operation actor: %w", err)
	}
	manager := sshtransport.NewManager()
	defer manager.Close()
	executor := deployment.NewExecutor(store, deployment.NewSSHRemote(manager))
	result, reconcileErr := executor.Reconcile(ctx, args[0], actor.Username)
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		return err
	}
	return reconcileErr
}

func runPlanOperation(ctx context.Context, store *state.Store, operation string, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: vps-pilot app %s <plan-digest>", operation)
	}
	actor, err := user.Current()
	if err != nil {
		return fmt.Errorf("resolve local operation actor: %w", err)
	}
	manager := sshtransport.NewManager()
	defer manager.Close()
	executor := deployment.NewExecutor(store, deployment.NewSSHRemote(manager))
	if operation == "preflight" {
		plan, err := executor.Preflight(ctx, args[0], actor.Username)
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(plan)
	}
	result, executeErr := executor.Execute(ctx, args[0], actor.Username)
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		return err
	}
	return executeErr
}

func approvePlan(ctx context.Context, store *state.Store, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: vps-pilot app approve <plan-digest>")
	}
	info, err := os.Stdin.Stat()
	if err != nil {
		return fmt.Errorf("inspect approval input: %w", err)
	}
	if info.Mode()&os.ModeCharDevice == 0 {
		return fmt.Errorf("approval requires a trusted interactive terminal")
	}
	snapshot, err := store.GetReleasePlan(ctx, args[0])
	if err != nil {
		return err
	}
	var plan application.ReleasePlan
	if err := json.Unmarshal([]byte(snapshot.PlanJSON), &plan); err != nil {
		return fmt.Errorf("decode stored release plan: %w", err)
	}
	if plan.Digest != args[0] || !application.HasValidDigest(plan) {
		return fmt.Errorf("stored release plan failed integrity validation")
	}
	if err := printApprovalPreview(plan); err != nil {
		return err
	}
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
}

func printApprovalPreview(plan application.ReleasePlan) error {
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
	return nil
}

func planRelease(ctx context.Context, store *state.Store, args []string) error {
	if len(args) != 3 {
		return fmt.Errorf("usage: vps-pilot app plan <application-id> <environment> <service,service>")
	}
	plan, err := planning.New(store).Create(ctx, args[0], args[1], strings.Split(args[2], ","))
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(plan)
}

func validateManifest(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: vps-pilot app validate <manifest.yaml>")
	}
	data, err := os.ReadFile(args[0])
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
}

func importManifest(ctx context.Context, store *state.Store, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: vps-pilot app import <manifest.yaml>")
	}
	data, err := os.ReadFile(args[0])
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
	app := state.Application{
		ID: manifest.Metadata.Name, Name: manifest.Metadata.Name,
		Digest: digest, Manifest: string(canonical),
	}
	if err := store.SaveApplication(ctx, app); err != nil {
		return err
	}
	fmt.Printf("imported %s %s\n", app.Name, app.Digest)
	return nil
}

func listApplications(ctx context.Context, store *state.Store) error {
	apps, err := store.ListApplications(ctx)
	if err != nil {
		return err
	}
	for _, app := range apps {
		fmt.Printf("%s\t%s\n", app.ID, app.Digest)
	}
	return nil
}

func printApplicationGraph(ctx context.Context, store *state.Store, args []string) error {
	manifest, _, err := loadApplicationManifest(ctx, store, args, "graph")
	if err != nil {
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
}

func printApplicationInventory(ctx context.Context, store *state.Store, args []string) error {
	manifest, app, err := loadApplicationManifest(ctx, store, args, "inventory")
	if err != nil {
		return err
	}
	inventory, err := application.BuildInventory(&manifest, app.Digest)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(inventory)
}

func loadApplicationManifest(ctx context.Context, store *state.Store, args []string, operation string) (application.Manifest, state.Application, error) {
	if len(args) != 1 {
		return application.Manifest{}, state.Application{}, fmt.Errorf("usage: vps-pilot app %s <application-id>", operation)
	}
	app, err := store.GetApplication(ctx, args[0])
	if err != nil {
		return application.Manifest{}, state.Application{}, err
	}
	var manifest application.Manifest
	if err := json.Unmarshal([]byte(app.Manifest), &manifest); err != nil {
		return application.Manifest{}, state.Application{}, fmt.Errorf("decode stored application manifest: %w", err)
	}
	return manifest, app, nil
}
