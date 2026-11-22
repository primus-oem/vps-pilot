package state

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestApprovalIsBoundAndConsumedOnce(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, filepath.Join(t.TempDir(), "private", "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.SaveReleasePlan(ctx, ReleasePlanSnapshot{
		Digest: "sha256:plan", CoreDigest: "sha256:core", ApplicationID: "app",
		Environment: "prod", ManifestDigest: "sha256:manifest", PlanJSON: "{}",
	}); err != nil {
		t.Fatal(err)
	}
	expiry := time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)
	record := ApprovalRecord{
		ID: "approval-id", PlanDigest: "sha256:plan", Actor: "operator",
		TargetDigest: "sha256:targets", ScopeDigest: "sha256:scope", ExpiresAt: expiry,
	}
	created := testOperationEvent("approval.created")
	if err := store.CreateApproval(ctx, record, created); err != nil {
		t.Fatal(err)
	}
	wrong := record
	wrong.PlanDigest = "sha256:other"
	if err := store.ConsumeApproval(ctx, wrong, testOperationEvent("approval.consumed")); !errors.Is(err, ErrApprovalUnavailable) {
		t.Fatalf("expected mismatched approval to fail, got %v", err)
	}
	if err := store.ConsumeApproval(ctx, record, testOperationEvent("approval.consumed")); err != nil {
		t.Fatal(err)
	}
	if err := store.ConsumeApproval(ctx, record, testOperationEvent("approval.consumed")); !errors.Is(err, ErrApprovalUnavailable) {
		t.Fatalf("expected consumed approval to be unavailable, got %v", err)
	}
}

func TestDeploymentLockLeaseAndJournalAreProtected(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, filepath.Join(t.TempDir(), "private", "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	expiry := time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)
	if err := store.AcquireDeploymentLock(ctx, "prod", "first", "sha256:a", expiry); err != nil {
		t.Fatal(err)
	}
	if err := store.AcquireDeploymentLock(ctx, "prod", "second", "sha256:b", expiry); !errors.Is(err, ErrDeploymentLocked) {
		t.Fatalf("expected active lock rejection, got %v", err)
	}
	if err := store.RefreshDeploymentLock(ctx, "prod", "first", "sha256:a", time.Now().Add(2*time.Minute).UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if err := store.RefreshDeploymentLock(ctx, "prod", "second", "sha256:b", time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)); !errors.Is(err, ErrDeploymentLockLost) {
		t.Fatalf("expected a non-holder to fail lease refresh, got %v", err)
	}
	if err := store.ReleaseDeploymentLock(ctx, "prod", "first", "sha256:a"); err != nil {
		t.Fatal(err)
	}
	event := testOperationEvent("deploy.preflight")
	if err := store.AppendOperationEvent(ctx, event); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE operation_journal SET status='error' WHERE event_id=?`, event.ID); err == nil {
		t.Fatal("expected journal update to be rejected")
	}
	if _, err := store.db.ExecContext(ctx, `DELETE FROM operation_journal WHERE event_id=?`, event.ID); err == nil {
		t.Fatal("expected journal deletion to be rejected")
	}
}

func testOperationEvent(eventType string) OperationEvent {
	return OperationEvent{
		ID: "event-" + eventType, CorrelationID: "correlation-1", PlanDigest: "sha256:plan",
		Actor: "operator", ResourceID: "app/prod", EventType: eventType, Status: "ok", MetadataJSON: "{}",
	}
}
