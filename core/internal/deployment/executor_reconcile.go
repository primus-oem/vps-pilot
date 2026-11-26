package deployment

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/primus-oem/vps-pilot/core/internal/application"
)

func (e *Executor) Reconcile(ctx context.Context, digest, actor string) (ReconcileResult, error) {
	plan, _, err := e.loadPlan(ctx, digest)
	if err != nil {
		return ReconcileResult{}, err
	}
	correlationID, err := newID()
	if err != nil {
		return ReconcileResult{}, err
	}
	result := ReconcileResult{
		Status: "ok", PlanDigest: plan.Digest, CorrelationID: correlationID,
		Observed: []string{}, Divergences: []string{},
	}
	if err := e.recordWithCorrelation(ctx, plan, actor, correlationID, "deployment.reconcile.started", "ok", "{}"); err != nil {
		return result, err
	}
	current, err := e.inspectPlan(ctx, plan, nil)
	if err != nil {
		result.Status = "error"
		_ = e.recordWithCorrelation(ctx, plan, actor, correlationID, "deployment.reconcile.failed", "error", "{}")
		return result, err
	}
	if !reflect.DeepEqual(sortedEvidence(plan.Preflight), sortedEvidence(current)) {
		result.Status = "divergent"
		result.Divergences = append(result.Divergences, "compose_config_or_runtime_changed")
	}
	selected := make(map[string]bool, len(plan.Selected))
	for _, name := range plan.Selected {
		selected[name] = true
	}
	for _, service := range plan.Services {
		if selected[service.Name] {
			result.Observed = append(result.Observed, service.Name)
		}
	}
	status := "ok"
	if result.Status != "ok" {
		status = "partial"
	}
	if err := e.recordWithCorrelation(ctx, plan, actor, correlationID, "deployment.reconcile.completed", status, "{}"); err != nil {
		result.Status = "partial"
		return result, err
	}
	return result, nil
}

func (e *Executor) verifySelectedHealth(ctx context.Context, plan application.ReleasePlan, selected map[string]bool, beforeCommand func() error) error {
	for _, group := range groupsFor(plan) {
		host, err := e.store.GetHost(ctx, group.target.SSHAlias)
		if err != nil {
			return errors.New("configured SSH target is unavailable during health verification")
		}
		if beforeCommand != nil {
			if err := beforeCommand(); err != nil {
				return err
			}
		}
		data, err := e.remote.ComposeStatus(ctx, host, group.project, group.file)
		if err != nil {
			return errors.New("post-deployment health status is unavailable")
		}
		statuses, err := parseComposeStatus(data)
		clear(data)
		if err != nil {
			return err
		}
		byService := make(map[string][]composeStatus)
		for _, status := range statuses {
			byService[status.Service] = append(byService[status.Service], status)
		}
		for _, service := range group.services {
			if !selected[service.Name] {
				continue
			}
			entries := byService[service.ComposeService]
			if len(entries) == 0 {
				return fmt.Errorf("service %q is missing after deployment", service.Name)
			}
			for _, entry := range entries {
				if !strings.EqualFold(entry.State, "running") || !strings.EqualFold(entry.Health, "healthy") {
					return fmt.Errorf("service %q did not pass its health gate", service.Name)
				}
			}
		}
	}
	return nil
}
