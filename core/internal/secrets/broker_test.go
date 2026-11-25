package secrets

import (
	"testing"
)

func TestProvisionRequestRejectsUnsafeScope(t *testing.T) {
	unsafe := []ProvisionRequest{
		{Project: "../app", Environment: "prod", Service: "api", Name: "DB_PASSWORD", Version: "v1"},
		{Project: "app", Environment: "prod", Service: "api", Name: "DB/PASSWORD", Version: "v1"},
		{Project: "app", Environment: "", Service: "api", Name: "DB_PASSWORD", Version: "v1"},
	}
	for _, request := range unsafe {
		if request.validate() == nil {
			t.Fatalf("expected unsafe request to be rejected: %#v", request)
		}
	}
}

func TestSecretReceiptTargetsAreRestricted(t *testing.T) {
	if safeSecretPath("/srv/vps-pilot/secrets/app/prod/API_PASSWORD.v1") == false {
		t.Fatal("expected managed secret path")
	}
	if safeSecretPath("/tmp/API_PASSWORD") {
		t.Fatal("accepted secret path outside managed root")
	}
}
