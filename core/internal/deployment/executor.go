package deployment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/primus-oem/vps-pilot/core/internal/approval"
	"github.com/primus-oem/vps-pilot/core/internal/planning"
	"github.com/primus-oem/vps-pilot/core/internal/state"
)

type Executor struct {
	store  *state.Store
	remote Remote
}

type DeploymentResult struct {
	Status        string   `json:"status"`
	PlanDigest    string   `json:"plan_digest"`
	CorrelationID string   `json:"correlation_id"`
	Attempted     []string `json:"attempted_services"`
	Applied       []string `json:"applied_services"`
}

type ReconcileResult struct {
	Status        string   `json:"status"`
	PlanDigest    string   `json:"plan_digest"`
	CorrelationID string   `json:"correlation_id"`
	Observed      []string `json:"observed_services"`
	Divergences   []string `json:"divergences"`
}

func NewExecutor(store *state.Store, remote Remote) *Executor {
	return &Executor{store: store, remote: remote}
}

func (e *Executor) Execute(ctx context.Context, digest, actor string) (result DeploymentResult, err error) {
	if e == nil || e.store == nil || e.remote == nil {
		return DeploymentResult{}, errors.New("deployment executor is not configured")
	}
	plan, _, err := e.loadPlan(ctx, digest)
	if err != nil {
		return DeploymentResult{}, err
	}
	if len(plan.Preflight) == 0 {
		return DeploymentResult{}, errors.New("release plan requires remote preflight before execution")
	}
	if !plan.Risk.ApprovalRequired {
		return DeploymentResult{}, errors.New("release plan is not marked for approval")
	}
	if actor == "" {
		return DeploymentResult{}, errors.New("deployment actor is required")
	}
	if err := planning.VerifyHostIdentities(ctx, e.store, plan); err != nil {
		return DeploymentResult{}, err
	}
	correlationID, err := newID()
	if err != nil {
		return DeploymentResult{}, err
	}
	result = DeploymentResult{
		Status: "error", PlanDigest: plan.Digest, CorrelationID: correlationID,
		Attempted: []string{}, Applied: []string{},
	}
	if err := e.recordWithCorrelation(ctx, plan, actor, correlationID, "deployment.execution.started", "ok", "{}"); err != nil {
		return result, err
	}
	locks, holder, err := e.acquireLocks(ctx, plan)
	if err != nil {
		_ = e.recordWithCorrelation(ctx, plan, actor, correlationID, "deployment.lock.denied", "denied", "{}")
		return result, err
	}
	defer func() {
		releaseCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if releaseErr := e.releaseLocks(releaseCtx, locks, holder, plan.Digest); releaseErr != nil {
			if err == nil {
				err = releaseErr
			} else {
				err = errors.Join(err, releaseErr)
			}
			if len(result.Applied) > 0 || len(result.Attempted) > 0 {
				result.Status = "partial"
			}
		}
	}()
	refresh := func() error { return e.refreshLocks(ctx, locks, holder, plan.Digest) }

	currentEvidence, err := e.inspectPlan(ctx, plan, refresh)
	if err != nil {
		_ = e.recordWithCorrelation(ctx, plan, actor, correlationID, "deployment.preflight.failed", "denied", "{}")
		return result, err
	}
	if !reflect.DeepEqual(sortedEvidence(plan.Preflight), sortedEvidence(currentEvidence)) {
		_ = e.recordWithCorrelation(ctx, plan, actor, correlationID, "deployment.preflight.changed", "denied", "{}")
		return result, errors.New("target configuration or runtime changed after approval")
	}
	if err := approval.AuthorizePlan(ctx, e.store, plan.Digest, actor); err != nil {
		_ = e.recordWithCorrelation(ctx, plan, actor, correlationID, "deployment.approval.denied", "denied", "{}")
		return result, err
	}

	selected := make(map[string]bool, len(plan.Selected))
	for _, name := range plan.Selected {
		selected[name] = true
	}
	for _, service := range plan.Services {
		if !selected[service.Name] {
			continue
		}
		for _, targetID := range service.Hosts {
			target, ok := targetFor(plan, targetID)
			if !ok {
				err = errors.New("release target disappeared from the approved plan")
				return e.failExecution(ctx, plan, actor, correlationID, result, err)
			}
			if err = refresh(); err != nil {
				return e.failExecution(ctx, plan, actor, correlationID, result, err)
			}
			if err = planning.VerifyHostIdentities(ctx, e.store, plan); err != nil {
				return e.failExecution(ctx, plan, actor, correlationID, result, err)
			}
			host, getErr := e.store.GetHost(ctx, target.SSHAlias)
			if getErr != nil {
				err = errors.New("configured SSH target is unavailable")
				return e.failExecution(ctx, plan, actor, correlationID, result, err)
			}
			if err = e.verifyCurrentConfig(ctx, plan, service, target, host); err != nil {
				return e.failExecution(ctx, plan, actor, correlationID, result, err)
			}
			metadata, marshalErr := json.Marshal(struct {
				Service string `json:"service"`
				Target  string `json:"target"`
			}{service.Name, target.ID})
			if marshalErr != nil {
				err = fmt.Errorf("encode deployment event: %w", marshalErr)
				return e.failExecution(ctx, plan, actor, correlationID, result, err)
			}
			if err = e.recordWithCorrelation(ctx, plan, actor, correlationID, "compose.up.started", "ok", string(metadata)); err != nil {
				return result, err
			}
			result.Attempted = append(result.Attempted, service.Name+"@"+target.ID)
			if err = e.remote.ComposeUp(ctx, host, service.ComposeProject, service.ComposeFile, service.ComposeService); err != nil {
				_ = e.recordWithCorrelation(ctx, plan, actor, correlationID, "compose.up.failed", "error", string(metadata))
				return e.failExecution(ctx, plan, actor, correlationID, result, errors.New("typed Compose operation failed"))
			}
			result.Applied = append(result.Applied, service.Name+"@"+target.ID)
			if err = e.recordWithCorrelation(ctx, plan, actor, correlationID, "compose.up.completed", "ok", string(metadata)); err != nil {
				result.Status = "partial"
				return result, err
			}
		}
	}
	if err = e.verifySelectedHealth(ctx, plan, selected, refresh); err != nil {
		return e.failExecution(ctx, plan, actor, correlationID, result, err)
	}
	result.Status = "ok"
	if err = e.recordWithCorrelation(ctx, plan, actor, correlationID, "deployment.execution.completed", "ok", "{}"); err != nil {
		result.Status = "partial"
		return result, err
	}
	return result, nil
}
