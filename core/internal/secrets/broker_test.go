package secrets

import (
	"testing"
)

func TestProvisionRequestRejectsUnsafeScope(t *testing.T) {
	unsafe := []ProvisionRequest{
		{Project: "../app", Environment: "prod", Service: "api", Name: "DB_PASSWORD", Version: "v1"},
		{Project: "app", Environment: "prod", Service: "api", Name: "DB/PASSWORD", Version: "v1"},
		{Project: "app", Environment: "", Service: "api", Name: "DB_PASSWORD", Version: "v1"},
		{Project: "app", Environment: "prod", Service: "api", Name: "DB_PASSWORD", Version: "../latest"},
	}
	for _, request := range unsafe {
		if request.validate() == nil {
			t.Fatalf("expected unsafe request to be rejected: %#v", request)
		}
	}
}

func TestSecretReceiptTargetsAreRestricted(t *testing.T) {
	if !safeSecretPath("/srv/vps-pilot/secrets/app/prod/api/API_PASSWORD.v1") {
		t.Fatal("expected managed secret path")
	}
	if safeSecretPath("/tmp/API_PASSWORD") {
		t.Fatal("accepted secret path outside managed root")
	}
	if safeSecretPath("/srv/vps-pilot/secrets/app/prod/api/../other/API_PASSWORD.v1") {
		t.Fatal("accepted secret path traversal")
	}
	if safeSecretPath("/srv/vps-pilot/secrets/app/prod/api/API_PASSWORD.v1/extra") {
		t.Fatal("accepted malformed secret path")
	}
}

func TestTargetPathBindsSecretToService(t *testing.T) {
	first, err := (ProvisionRequest{Project: "app", Environment: "prod", Service: "api", Name: "TOKEN", Version: "v1"}).TargetPath()
	if err != nil {
		t.Fatal(err)
	}
	second, err := (ProvisionRequest{Project: "app", Environment: "prod", Service: "worker", Name: "TOKEN", Version: "v1"}).TargetPath()
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("different services must have isolated secret paths")
	}
}
