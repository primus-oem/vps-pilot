package planning

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/primus-oem/vps-pilot/core/internal/application"
	"github.com/primus-oem/vps-pilot/core/internal/state"
)

const plannerManifest = `apiVersion: vpspilot.dev/v1alpha1
kind: Application
metadata:
  name: planner-test
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
  api:
    image:
      registry: registry.example.test/acme/api
      digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    deploy:
      driver: compose
      project: release
      file: /srv/apps/release/compose.yaml
      service: api
      hosts: [staging]
`

func TestPlannerPersistsAndComparesImmutablePlans(t *testing.T) {
	ctx := context.Background()
	store, err := state.Open(ctx, filepath.Join(t.TempDir(), "private", "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
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
	saveManifest := func(raw string) {
		t.Helper()
		manifest, err := application.Parse([]byte(raw))
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
	}
	saveManifest(plannerManifest)
	planner := New(store)
	first, err := planner.Create(ctx, "planner-test", "staging", []string{"api"})
	if err != nil {
		t.Fatal(err)
	}
	if first.Diff.Status != "baseline_unavailable" {
		t.Fatalf("expected explicit missing baseline, got %#v", first.Diff)
	}

	updated := strings.Replace(plannerManifest, "sha256:aaaaaaaa", "sha256:bbbbbbbb", 1)
	saveManifest(updated)
	second, err := planner.Create(ctx, "planner-test", "staging", []string{"api"})
	if err != nil {
		t.Fatal(err)
	}
	if second.Diff.Status != "changed" || second.Diff.BaselineDigest != first.Digest {
		t.Fatalf("expected diff against first immutable plan, got %#v", second.Diff)
	}
	repeated, err := planner.Create(ctx, "planner-test", "staging", []string{"api"})
	if err != nil {
		t.Fatal(err)
	}
	if repeated.Digest != second.Digest {
		t.Fatalf("repeated plan digest drifted: %s != %s", repeated.Digest, second.Digest)
	}
	if !application.HasValidDigest(repeated) {
		t.Fatal("expected repeat plan digest to verify")
	}
}
