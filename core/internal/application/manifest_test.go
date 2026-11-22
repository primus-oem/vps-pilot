package application

import (
	"strings"
	"testing"
)

const fixture = `apiVersion: vpspilot.dev/v1alpha1
kind: Application
metadata:
  name: sample
services:
  database:
    managed: true
    deploy:
      driver: compose
      project: sample
      file: /srv/apps/sample/compose.yaml
      service: postgres
  api:
    deploy:
      driver: compose
      project: sample
      file: /srv/apps/sample/compose.yaml
      service: api
    dependsOn: [database]
`

func TestParseAndValidateFixture(t *testing.T) {
	manifest, err := Parse([]byte(fixture))
	if err != nil {
		t.Fatal(err)
	}
	order, err := TopologicalOrder(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(order) != 2 || order[0] != "database" {
		t.Fatalf("unexpected order: %#v", order)
	}
}

func TestParseRejectsUnknownField(t *testing.T) {
	_, err := Parse([]byte(fixture + "unexpected: true\n"))
	if err == nil || !strings.Contains(err.Error(), "field unexpected not found") {
		t.Fatalf("expected strict unknown-field error, got %v", err)
	}
}

func TestParseRejectsCycle(t *testing.T) {
	data := fixture + "  worker:\n    deploy:\n      driver: compose\n      project: sample\n      file: /srv/apps/sample/compose.yaml\n      service: worker\n    dependsOn: [api]\n"
	data = strings.Replace(data, "    dependsOn: [database]\n", "    dependsOn: [database, worker]\n", 1)
	if _, err := Parse([]byte(data)); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("expected cycle error, got %v", err)
	}
}

func TestTopologicalOrderIsDeterministic(t *testing.T) {
	manifest, err := Parse([]byte(fixture))
	if err != nil {
		t.Fatal(err)
	}
	first, err := TopologicalOrder(manifest)
	if err != nil {
		t.Fatal(err)
	}
	second, err := TopologicalOrder(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(first, ",") != strings.Join(second, ",") {
		t.Fatalf("nondeterministic order: %#v %#v", first, second)
	}
}

func TestReleasePlanBindsTargetsArtifactsAndConfig(t *testing.T) {
	manifest, err := Parse([]byte(releaseFixture))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := CreateReleasePlan(manifest, "staging", []string{"api"})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Services) != 2 || plan.Services[0].Name != "db" || len(plan.Targets) != 1 {
		t.Fatalf("unexpected plan: %#v", plan)
	}
	if !HasValidDigest(plan) {
		t.Fatal("expected valid plan digest")
	}
	if plan.Risk.Level != "high" || !plan.Risk.ApprovalRequired {
		t.Fatalf("expected stateful plan to require high-risk approval: %#v", plan.Risk)
	}
	plan.Targets[0].SSHAlias = "other"
	if HasValidDigest(plan) {
		t.Fatal("expected target change to invalidate digest")
	}
}

func TestReleasePlanComparesAgainstPreviousPlan(t *testing.T) {
	manifest, err := Parse([]byte(releaseFixture))
	if err != nil {
		t.Fatal(err)
	}
	previous, err := CreateReleasePlan(manifest, "staging", []string{"api"})
	if err != nil {
		t.Fatal(err)
	}
	service := manifest.Services["api"]
	service.Image.Digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	manifest.Services["api"] = service
	current, err := CreateReleasePlan(manifest, "staging", []string{"api"})
	if err != nil {
		t.Fatal(err)
	}
	diff := CompareReleasePlans(previous, current)
	if diff.Status != "changed" || len(diff.Changes) == 0 {
		t.Fatalf("expected non-empty release diff, got %#v", diff)
	}
	foundImage := false
	for _, change := range diff.Changes {
		if change.Resource == "service:api" && change.Action == "updated" && strings.Contains(strings.Join(change.Fields, ","), "image") {
			foundImage = true
		}
	}
	if !foundImage {
		t.Fatalf("expected image change in diff: %#v", diff.Changes)
	}
}

func TestPolicyCanRequireHealthChecks(t *testing.T) {
	manifest, err := Parse([]byte(releaseFixture))
	if err != nil {
		t.Fatal(err)
	}
	manifest.Policies = map[string]Policy{"staging": {RequireHealth: true}}
	if _, err := CreateReleasePlan(manifest, "staging", []string{"api"}); err == nil {
		t.Fatal("expected policy to reject missing health checks")
	}
}

func TestReleasePlanRejectsUnallowlistedRegistryAndPath(t *testing.T) {
	manifest, err := Parse([]byte(releaseFixture))
	if err != nil {
		t.Fatal(err)
	}
	service := manifest.Services["api"]
	service.Deploy.File = "/srv/apps/outside/compose.yaml"
	manifest.Services["api"] = service
	if _, err := CreateReleasePlan(manifest, "staging", []string{"api"}); err == nil {
		t.Fatal("expected unsafe file path to be rejected")
	}
	service.Deploy.File = "/srv/apps/release/compose.yaml"
	service.Image.Registry = "evil.example.test/acme/api"
	manifest.Services["api"] = service
	if _, err := CreateReleasePlan(manifest, "staging", []string{"api"}); err == nil {
		t.Fatal("expected unallowlisted registry to be rejected")
	}
}

func TestParseRejectsMalformedSecondDocument(t *testing.T) {
	if _, err := Parse([]byte(fixture + "---\ninvalid: [")); err == nil {
		t.Fatal("expected malformed trailing document to be rejected")
	}
}

func TestParseRejectsPlaintextSecretValues(t *testing.T) {
	data := strings.Replace(fixture, "    dependsOn: [database]\n", "    dependsOn: [database]\n    secrets:\n      DB_PASSWORD:\n        ref: plaintext-value\n        injection: file\n", 1)
	if _, err := Parse([]byte(data)); err == nil {
		t.Fatal("expected non-reference secret value to be rejected")
	}
}

const releaseFixture = `apiVersion: vpspilot.dev/v1alpha1
kind: Application
metadata:
  name: release-app
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
  db:
    managed: true
    stateful: true
    deploy:
      driver: compose
      project: release
      file: /srv/apps/release/compose.yaml
      service: postgres
      hosts: [staging]
  api:
    role: api
    image:
      registry: registry.example.test/acme/api
      digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    deploy:
      driver: compose
      project: release
      file: /srv/apps/release/compose.yaml
      service: api
      hosts: [staging]
    dependsOn: [db]
`
