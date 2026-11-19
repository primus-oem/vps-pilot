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
	data = strings.Replace(data, "  api:\n", "  api:\n", 1)
	data = strings.Replace(data, "    dependsOn: [database]\n", "    dependsOn: [database, worker]\n", 1)
	_, err := Parse([]byte(data))
	if err == nil || !strings.Contains(err.Error(), "cycle") {
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
