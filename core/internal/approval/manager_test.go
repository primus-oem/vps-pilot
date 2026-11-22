package approval

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/primus-oem/vps-pilot/core/internal/application"
	"github.com/primus-oem/vps-pilot/core/internal/planning"
	"github.com/primus-oem/vps-pilot/core/internal/state"
)

const approvedManifest = `apiVersion: vpspilot.dev/v1alpha1
kind: Application
metadata:
  name: approval-test
environments:
  production:
    protected: true
    requireApproval: true
    hosts: [prod]
hosts:
  prod:
    sshAlias: prod-ssh
    allowedRoot: /srv/apps/prod
    hostKeyRef: known_hosts/prod
services:
  database:
    managed: true
    stateful: true
    deploy:
      driver: compose
      project: prod
      file: /srv/apps/prod/compose.yaml
      service: postgres
      hosts: [prod]
`

func TestApprovalBindsStoredPlanAndActor(t *testing.T) {
	ctx := context.Background()
	store, err := state.Open(ctx, filepath.Join(t.TempDir(), "private", "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(knownHosts, []byte("prod-ssh ssh-ed25519 AAAATEST\n"), 0600); err != nil {
		t.Fatal(err)
	}
	identity := filepath.Join(t.TempDir(), "id_test")
	if err := os.WriteFile(identity, []byte("test identity placeholder"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertHost(ctx, state.Host{
		Environment: "production", SSHAlias: "prod-ssh", Host: "127.0.0.1",
		User: "deploy", IdentityFile: identity, KnownHostsFile: knownHosts, Port: 22, TimeoutSeconds: 10,
	}); err != nil {
		t.Fatal(err)
	}
	manifest, err := application.Parse([]byte(approvedManifest))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveApplication(ctx, state.Application{
		ID: manifest.Metadata.Name, Name: manifest.Metadata.Name,
		Digest: application.ManifestDigest(manifest), Manifest: string(encoded),
	}); err != nil {
		t.Fatal(err)
	}
	plan, err := planning.New(store).Create(ctx, "approval-test", "production", []string{"database"})
	if err != nil {
		t.Fatal(err)
	}
	if err := ApprovePlan(ctx, store, plan.Digest, "operator"); err == nil {
		t.Fatal("expected approval to require remote preflight")
	}
	original, err := store.GetReleasePlan(ctx, plan.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := application.BindPreflight(&plan, []application.ComposePreflight{{
		TargetID: "prod", Project: "prod", File: "/srv/apps/prod/compose.yaml",
		ConfigDigest: "sha256:config", RuntimeDigest: "sha256:runtime",
	}}); err != nil {
		t.Fatal(err)
	}
	planJSON, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	original.Digest = plan.Digest
	original.PlanJSON = string(planJSON)
	if err := store.SaveReleasePlan(ctx, original); err != nil {
		t.Fatal(err)
	}
	if !plan.Risk.ApprovalRequired {
		t.Fatal("expected approval requirement")
	}
	if err := ApprovePlan(ctx, store, plan.Digest, "operator"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(knownHosts, []byte("prod-ssh ssh-ed25519 AAAACHANGED\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := AuthorizePlan(ctx, store, plan.Digest, "operator"); err == nil {
		t.Fatal("expected changed SSH identity to invalidate approval")
	}
	if err := os.WriteFile(knownHosts, []byte("prod-ssh ssh-ed25519 AAAATEST\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := AuthorizePlan(ctx, store, plan.Digest, "other-operator"); !errors.Is(err, state.ErrApprovalUnavailable) {
		t.Fatalf("expected actor mismatch to be denied, got %v", err)
	}
	if err := AuthorizePlan(ctx, store, plan.Digest, "operator"); err != nil {
		t.Fatal(err)
	}
	if err := AuthorizePlan(ctx, store, plan.Digest, "operator"); !errors.Is(err, state.ErrApprovalUnavailable) {
		t.Fatalf("expected one-time approval to be consumed, got %v", err)
	}
}
