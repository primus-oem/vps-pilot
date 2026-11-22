package approval

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/primus-oem/vps-pilot/core/internal/application"
	"github.com/primus-oem/vps-pilot/core/internal/planning"
	"github.com/primus-oem/vps-pilot/core/internal/state"
)

const ApprovalTTL = 5 * time.Minute

func ApprovePlan(ctx context.Context, store *state.Store, digest, actor string) error {
	plan, err := loadPlan(ctx, store, digest)
	if err != nil {
		return err
	}
	if !plan.Risk.ApprovalRequired {
		return errors.New("release plan does not require approval")
	}
	if len(plan.Preflight) == 0 {
		return errors.New("remote preflight is required before approval")
	}
	if err := planning.VerifyHostIdentities(ctx, store, plan); err != nil {
		return err
	}
	targetDigest, scopeDigest, err := planBinding(plan, actor)
	if err != nil {
		return err
	}
	identifier, err := randomID()
	if err != nil {
		return err
	}
	hashedID := sha256.Sum256([]byte(identifier))
	record := state.ApprovalRecord{
		ID: hex.EncodeToString(hashedID[:]), PlanDigest: plan.Digest, Actor: actor,
		TargetDigest: targetDigest, ScopeDigest: scopeDigest,
		ExpiresAt: time.Now().Add(ApprovalTTL).UTC().Format(time.RFC3339Nano),
	}
	correlationID, err := randomID()
	if err != nil {
		return err
	}
	event := state.OperationEvent{
		ID: identifier, CorrelationID: correlationID, PlanDigest: digest, Actor: actor,
		ResourceID: plan.Application + "/" + plan.Environment,
		EventType:  "approval.created", Status: "ok",
		MetadataJSON: fmt.Sprintf(`{"expires_at":%q,"risk_level":%q}`, record.ExpiresAt, plan.Risk.Level),
	}
	return store.CreateApproval(ctx, record, event)
}

func AuthorizePlan(ctx context.Context, store *state.Store, digest, actor string) error {
	plan, err := loadPlan(ctx, store, digest)
	if err != nil {
		return err
	}
	if !plan.Risk.ApprovalRequired {
		return errors.New("release plan does not require approval")
	}
	if len(plan.Preflight) == 0 {
		return errors.New("remote preflight is required before execution")
	}
	if err := planning.VerifyHostIdentities(ctx, store, plan); err != nil {
		return err
	}
	targetDigest, scopeDigest, err := planBinding(plan, actor)
	if err != nil {
		return err
	}
	record := state.ApprovalRecord{
		PlanDigest: plan.Digest, Actor: actor, TargetDigest: targetDigest, ScopeDigest: scopeDigest,
	}
	eventID, err := randomID()
	if err != nil {
		return err
	}
	correlationID, err := randomID()
	if err != nil {
		return err
	}
	event := state.OperationEvent{
		ID: eventID, CorrelationID: correlationID, PlanDigest: digest, Actor: actor,
		ResourceID: plan.Application + "/" + plan.Environment,
		EventType:  "approval.consumed", Status: "ok", MetadataJSON: "{}",
	}
	return store.ConsumeApproval(ctx, record, event)
}

func loadPlan(ctx context.Context, store *state.Store, digest string) (application.ReleasePlan, error) {
	snapshot, err := store.GetReleasePlan(ctx, digest)
	if err != nil {
		return application.ReleasePlan{}, err
	}
	var plan application.ReleasePlan
	if err := json.Unmarshal([]byte(snapshot.PlanJSON), &plan); err != nil {
		return application.ReleasePlan{}, fmt.Errorf("decode stored release plan: %w", err)
	}
	if plan.Digest != digest || !application.HasValidDigest(plan) {
		return application.ReleasePlan{}, errors.New("stored release plan failed integrity validation")
	}
	return plan, nil
}

func planBinding(plan application.ReleasePlan, actor string) (string, string, error) {
	if actor == "" {
		return "", "", errors.New("approval actor is required")
	}
	targetDigest, err := digestJSON(plan.Targets)
	if err != nil {
		return "", "", err
	}
	scopeDigest, err := digestJSON(struct {
		Application string                  `json:"application"`
		Environment string                  `json:"environment"`
		Selected    []string                `json:"selected"`
		Risk        application.RiskSummary `json:"risk"`
	}{plan.Application, plan.Environment, plan.Selected, plan.Risk})
	if err != nil {
		return "", "", err
	}
	return targetDigest, scopeDigest, nil
}

func digestJSON(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("canonicalize approval binding: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func randomID() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate operation identifier: %w", err)
	}
	return hex.EncodeToString(value), nil
}
