package deployment

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/primus-oem/vps-pilot/core/internal/application"
	"github.com/primus-oem/vps-pilot/core/internal/approval"
	"github.com/primus-oem/vps-pilot/core/internal/planning"
	"github.com/primus-oem/vps-pilot/core/internal/state"
)

const deployManifest = `apiVersion: vpspilot.dev/v1alpha1
kind: Application
metadata:
  name: deploy-test
environments:
  staging:
    hosts: [staging]
    allowedRegistries: [registry.example.test]
hosts:
  staging:
    sshAlias: staging-ssh
    allowedRoot: /srv/apps/release
    hostKeyRef: known_hosts/staging
services:
  database:
    managed: true
    stateful: true
    health:
      type: compose
      urlRef: database-health
    deploy:
      driver: compose
      project: release
      file: /srv/apps/release/compose.yaml
      service: postgres
      hosts: [staging]
  api:
    image:
      registry: registry.example.test/acme/api
      digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    health:
      type: compose
      urlRef: api-health
      expectedStatus: 200
    deploy:
      driver: compose
      project: release
      file: /srv/apps/release/compose.yaml
      service: api
      hosts: [staging]
    dependsOn: [database]
`

const safeComposeConfig = `{
  "services": {
    "postgres": {"image":"postgres:16","healthcheck":{"test":["CMD","pg_isready"]}},
    "api": {
      "image":"registry.example.test/acme/api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "healthcheck":{"test":["CMD","/health"]}
    }
  }
}`

type fakeRemote struct {
	config      []byte
	status      []byte
	upCalls     []string
	upError     error
	configCalls int
	statusCalls int
	checkCalls  int
}

func (r *fakeRemote) CheckComposeFile(_ context.Context, _ state.Host, root, file string) error {
	r.checkCalls++
	return validateRemoteTarget(root, file)
}

func (r *fakeRemote) ComposeConfig(context.Context, state.Host, string, string) ([]byte, error) {
	r.configCalls++
	return append([]byte(nil), r.config...), nil
}

func (r *fakeRemote) ComposeStatus(context.Context, state.Host, string, string) ([]byte, error) {
	r.statusCalls++
	return append([]byte(nil), r.status...), nil
}

func (r *fakeRemote) ComposeUp(_ context.Context, _ state.Host, _, _, service string) error {
	r.upCalls = append(r.upCalls, service)
	return r.upError
}

func TestPreflightBindsComposeConfigAndExecutionConsumesApproval(t *testing.T) {
	ctx := context.Background()
	store, remote, executor, plan := setupExecutor(t, safeComposeConfig)
	preflighted, err := executor.Preflight(ctx, plan.Digest, "operator")
	if err != nil {
		t.Fatal(err)
	}
	if preflighted.Digest == plan.Digest || len(preflighted.Preflight) != 1 {
		t.Fatalf("expected preflight evidence to create a new plan digest: %#v", preflighted)
	}
	for _, finding := range preflighted.Risk.Findings {
		if finding.Code == "compose_config_not_preflighted" {
			t.Fatal("expected preflight warning to be cleared")
		}
	}
	snapshot, err := store.GetReleasePlan(ctx, preflighted.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(snapshot.PlanJSON, "secret-must-not-be-persisted") {
		t.Fatal("Compose environment value was persisted")
	}
	if err := approval.ApprovePlan(ctx, store, preflighted.Digest, "operator"); err != nil {
		t.Fatal(err)
	}
	result, err := executor.Execute(ctx, preflighted.Digest, "operator")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "ok" || len(result.Applied) != 1 || len(remote.upCalls) != 1 || remote.upCalls[0] != "api" {
		t.Fatalf("unexpected deployment result: %#v calls=%#v", result, remote.upCalls)
	}
	if _, err := executor.Execute(ctx, preflighted.Digest, "operator"); !errors.Is(err, state.ErrApprovalUnavailable) {
		t.Fatalf("expected approval replay to be denied, got %v", err)
	}
	if len(remote.upCalls) != 1 {
		t.Fatalf("replayed approval executed again: %#v", remote.upCalls)
	}
	events, err := store.ListOperationEvents(ctx, preflighted.Digest, 100)
	if err != nil {
		t.Fatal(err)
	}
	completed := 0
	for _, event := range events {
		if event.EventType == "compose.up.completed" {
			completed++
		}
	}
	if completed != 1 {
		t.Fatalf("expected one successful operation journal event, got %d", completed)
	}
}

func TestExecutionRejectsComposeDriftBeforeConsumingApproval(t *testing.T) {
	ctx := context.Background()
	store, remote, executor, plan := setupExecutor(t, safeComposeConfig)
	preflighted, err := executor.Preflight(ctx, plan.Digest, "operator")
	if err != nil {
		t.Fatal(err)
	}
	if err := approval.ApprovePlan(ctx, store, preflighted.Digest, "operator"); err != nil {
		t.Fatal(err)
	}
	remote.config = append([]byte(safeComposeConfig), ' ')
	if _, err := executor.Execute(ctx, preflighted.Digest, "operator"); err == nil {
		t.Fatal("expected post-approval Compose drift to be rejected")
	}
	if len(remote.upCalls) != 0 {
		t.Fatalf("Compose mutation ran after drift: %#v", remote.upCalls)
	}
}

func TestPreflightRejectsPrivilegedAndUnhealthyConfiguration(t *testing.T) {
	ctx := context.Background()
	privileged := strings.Replace(safeComposeConfig, `"healthcheck":{"test":["CMD","/health"]}`, `"healthcheck":{"test":["CMD","/health"]},"privileged":true`, 1)
	_, _, executor, plan := setupExecutor(t, privileged)
	if _, err := executor.Preflight(ctx, plan.Digest, "operator"); err == nil {
		t.Fatal("expected privileged Compose service to be rejected")
	}
}

func TestPreflightRejectsUnclassifiedEnvironmentValues(t *testing.T) {
	withEnv := strings.Replace(safeComposeConfig, `"healthcheck":{"test":["CMD","/health"]}`, `"healthcheck":{"test":["CMD","/health"]},"environment":{"API_PASSWORD":"not-for-log"}`, 1)
	_, _, executor, plan := setupExecutor(t, withEnv)
	if _, err := executor.Preflight(context.Background(), plan.Digest, "operator"); err == nil {
		t.Fatal("expected environment values without secret broker to be rejected")
	}
}

func TestExecutionPartialFailureIsReportedAndJournaled(t *testing.T) {
	ctx := context.Background()
	store, remote, executor, plan := setupExecutor(t, safeComposeConfig)
	preflighted, err := executor.Preflight(ctx, plan.Digest, "operator")
	if err != nil {
		t.Fatal(err)
	}
	if err := approval.ApprovePlan(ctx, store, preflighted.Digest, "operator"); err != nil {
		t.Fatal(err)
	}
	remote.upError = errors.New("injected Compose failure")
	result, err := executor.Execute(ctx, preflighted.Digest, "operator")
	if err == nil {
		t.Fatal("expected injected Compose failure")
	}
	if result.Status != "partial" || len(result.Attempted) != 1 {
		t.Fatalf("unexpected partial-failure result: %#v", result)
	}
}

func TestReconcileReportsRuntimeDivergence(t *testing.T) {
	ctx := context.Background()
	_, _, executor, plan := setupExecutor(t, safeComposeConfig)
	preflighted, err := executor.Preflight(ctx, plan.Digest, "operator")
	if err != nil {
		t.Fatal(err)
	}
	result, err := executor.Reconcile(ctx, preflighted.Digest, "operator")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "ok" || len(result.Observed) != 1 {
		t.Fatalf("unexpected reconcile result: %#v", result)
	}
}

func setupExecutor(t *testing.T, composeConfig string) (*state.Store, *fakeRemote, *Executor, application.ReleasePlan) {
	t.Helper()
	ctx := context.Background()
	store, err := state.Open(ctx, filepath.Join(t.TempDir(), "private", "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(knownHosts, []byte("staging-ssh ssh-ed25519 AAAATEST\n"), 0600); err != nil {
		t.Fatal(err)
	}
	identity := filepath.Join(t.TempDir(), "id_test")
	if err := os.WriteFile(identity, []byte("test identity placeholder"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertHost(ctx, state.Host{
		Environment: "staging", SSHAlias: "staging-ssh", Host: "127.0.0.1",
		User: "deploy", IdentityFile: identity, KnownHostsFile: knownHosts, Port: 22, TimeoutSeconds: 10,
	}); err != nil {
		t.Fatal(err)
	}
	manifest, err := application.Parse([]byte(deployManifest))
	if err != nil {
		t.Fatal(err)
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveApplication(ctx, state.Application{
		ID: manifest.Metadata.Name, Name: manifest.Metadata.Name,
		Digest: application.ManifestDigest(manifest), Manifest: string(manifestJSON),
	}); err != nil {
		t.Fatal(err)
	}
	plan, err := planning.New(store).Create(ctx, "deploy-test", "staging", []string{"api"})
	if err != nil {
		t.Fatal(err)
	}
	remote := &fakeRemote{
		config: []byte(composeConfig),
		status: []byte(`[{"Service":"postgres","State":"running","Health":"healthy"},{"Service":"api","State":"running","Health":"healthy"}]`),
	}
	return store, remote, NewExecutor(store, remote), plan
}
