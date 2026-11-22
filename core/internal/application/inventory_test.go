package application

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildInventoryIsDeterministicAndOmitsSecretReferences(t *testing.T) {
	data := strings.Replace(releaseFixture, "  api:\n", "  api:\n    repository: {provider: github, project: org/api}\n    secrets:\n      DB_PASSWORD:\n        ref: vault://release/staging/database-password\n        injection: file\n", 1)
	manifest, err := Parse([]byte(data))
	if err != nil {
		t.Fatal(err)
	}

	inventory, err := BuildInventory(manifest, "sha256:manifest")
	if err != nil {
		t.Fatal(err)
	}
	if len(inventory.Services) != 2 || inventory.Services[0].Name != "db" || inventory.Services[1].Name != "api" {
		t.Fatalf("unexpected service order: %#v", inventory.Services)
	}
	api := inventory.Services[1]
	if api.Repository != "org/api" || len(api.Secrets) != 1 {
		t.Fatalf("unexpected service metadata: %#v", api)
	}
	binding := api.Secrets[0]
	if binding.Name != "DB_PASSWORD" || binding.Source != "vault" || binding.Status != "configured_unverified" {
		t.Fatalf("unexpected secret status: %#v", binding)
	}
	encoded, err := json.Marshal(inventory)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "vault://") || strings.Contains(string(encoded), "database-password") {
		t.Fatalf("inventory exposed secret reference: %s", encoded)
	}

	again, err := BuildInventory(manifest, "sha256:manifest")
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, _ := json.Marshal(inventory)
	secondJSON, _ := json.Marshal(again)
	if string(firstJSON) != string(secondJSON) {
		t.Fatal("inventory output is not deterministic")
	}
}
