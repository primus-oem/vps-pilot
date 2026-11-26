package deployment

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/primus-oem/vps-pilot/core/internal/application"
	"github.com/primus-oem/vps-pilot/core/internal/state"
)

type deploymentLock struct {
	scope string
}

func (e *Executor) acquireLocks(ctx context.Context, plan application.ReleasePlan) ([]deploymentLock, string, error) {
	holder, err := newID()
	if err != nil {
		return nil, "", err
	}
	targets := append([]application.ReleaseTarget(nil), plan.Targets...)
	sort.Slice(targets, func(i, j int) bool { return targets[i].SSHAlias < targets[j].SSHAlias })
	locks := make([]deploymentLock, 0, len(targets))
	for _, target := range targets {
		scope := "host:" + target.SSHAlias
		expiry := time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339Nano)
		if err := e.store.AcquireDeploymentLock(ctx, scope, holder, plan.Digest, expiry); err != nil {
			_ = e.releaseLocks(context.Background(), locks, holder, plan.Digest)
			return nil, "", err
		}
		locks = append(locks, deploymentLock{scope: scope})
	}
	return locks, holder, nil
}

func (e *Executor) refreshLocks(ctx context.Context, locks []deploymentLock, holder, digest string) error {
	expiry := time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339Nano)
	for _, lock := range locks {
		if err := e.store.RefreshDeploymentLock(ctx, lock.scope, holder, digest, expiry); err != nil {
			return err
		}
	}
	return nil
}

func (e *Executor) releaseLocks(ctx context.Context, locks []deploymentLock, holder, digest string) error {
	var result error
	for i := len(locks) - 1; i >= 0; i-- {
		if err := e.store.ReleaseDeploymentLock(ctx, locks[i].scope, holder, digest); err != nil {
			result = errors.Join(result, err)
		}
	}
	return result
}

func (e *Executor) failExecution(ctx context.Context, plan application.ReleasePlan, actor, correlation string, result DeploymentResult, cause error) (DeploymentResult, error) {
	result.Status = "error"
	status := "error"
	if len(result.Applied) > 0 || len(result.Attempted) > 0 {
		result.Status = "partial"
		status = "partial"
	}
	if err := e.recordWithCorrelation(ctx, plan, actor, correlation, "deployment.execution.failed", status, "{}"); err != nil {
		return result, errors.Join(cause, err)
	}
	return result, cause
}

func (e *Executor) record(ctx context.Context, plan application.ReleasePlan, actor, eventType, status, metadata string) error {
	correlationID, err := newID()
	if err != nil {
		return err
	}
	return e.recordWithCorrelation(ctx, plan, actor, correlationID, eventType, status, metadata)
}

func (e *Executor) recordWithCorrelation(ctx context.Context, plan application.ReleasePlan, actor, correlationID, eventType, status, metadata string) error {
	eventID, err := newID()
	if err != nil {
		return err
	}
	return e.store.AppendOperationEvent(ctx, state.OperationEvent{
		ID: eventID, CorrelationID: correlationID, PlanDigest: plan.Digest, Actor: actor,
		ResourceID: plan.Application + "/" + plan.Environment,
		EventType:  eventType, Status: status, MetadataJSON: metadata,
	})
}

func newID() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate deployment identifier: %w", err)
	}
	return hex.EncodeToString(value), nil
}
