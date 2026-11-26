package deployment

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/primus-oem/vps-pilot/core/internal/application"
	"github.com/primus-oem/vps-pilot/core/internal/planning"
	"github.com/primus-oem/vps-pilot/core/internal/state"
)

func (e *Executor) Preflight(ctx context.Context, digest, actor string) (application.ReleasePlan, error) {
	if e == nil || e.store == nil || e.remote == nil {
		return application.ReleasePlan{}, errors.New("deployment executor is not configured")
	}
	plan, snapshot, err := e.loadPlan(ctx, digest)
	if err != nil {
		return application.ReleasePlan{}, err
	}
	if err := planning.VerifyHostIdentities(ctx, e.store, plan); err != nil {
		return application.ReleasePlan{}, err
	}
	if err := e.record(ctx, plan, actor, "deployment.preflight.started", "ok", "{}"); err != nil {
		return application.ReleasePlan{}, err
	}
	evidence, err := e.inspectPlan(ctx, plan, nil)
	if err != nil {
		_ = e.record(ctx, plan, actor, "deployment.preflight.failed", "error", "{}")
		return application.ReleasePlan{}, err
	}
	if err := application.BindPreflight(&plan, evidence); err != nil {
		return application.ReleasePlan{}, err
	}
	coreDigest, err := application.ComparisonFingerprint(plan)
	if err != nil || coreDigest != snapshot.CoreDigest {
		return application.ReleasePlan{}, errors.New("preflight changed release scope or policy")
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		return application.ReleasePlan{}, fmt.Errorf("encode preflight plan: %w", err)
	}
	snapshot.Digest = plan.Digest
	snapshot.PlanJSON = string(encoded)
	if err := e.store.SaveReleasePlan(ctx, snapshot); err != nil {
		return application.ReleasePlan{}, err
	}
	if err := e.record(ctx, plan, actor, "deployment.preflight.completed", "ok", "{}"); err != nil {
		return application.ReleasePlan{}, err
	}
	return plan, nil
}

func (e *Executor) loadPlan(ctx context.Context, digest string) (application.ReleasePlan, state.ReleasePlanSnapshot, error) {
	snapshot, err := e.store.GetReleasePlan(ctx, digest)
	if err != nil {
		return application.ReleasePlan{}, state.ReleasePlanSnapshot{}, err
	}
	var plan application.ReleasePlan
	if err := json.Unmarshal([]byte(snapshot.PlanJSON), &plan); err != nil {
		return application.ReleasePlan{}, state.ReleasePlanSnapshot{}, errors.New("stored release plan is invalid")
	}
	coreDigest, err := application.ComparisonFingerprint(plan)
	if err != nil || plan.Digest != digest || snapshot.Digest != digest ||
		coreDigest != snapshot.CoreDigest || !application.HasValidDigest(plan) {
		return application.ReleasePlan{}, state.ReleasePlanSnapshot{}, errors.New("stored release plan failed integrity validation")
	}
	return plan, snapshot, nil
}

func (e *Executor) verifyCurrentConfig(ctx context.Context, plan application.ReleasePlan, selected application.ReleaseService, target application.ReleaseTarget, host state.Host) error {
	if err := validateRemoteTarget(target.AllowedRoot, selected.ComposeFile); err != nil {
		return err
	}
	if err := e.remote.CheckComposeFile(ctx, host, target.AllowedRoot, selected.ComposeFile); err != nil {
		return err
	}
	data, err := e.remote.ComposeConfig(ctx, host, selected.ComposeProject, selected.ComposeFile)
	if err != nil {
		return errors.New("remote Compose configuration changed or is unavailable")
	}
	group := servicesForTargetFile(plan, target.ID, selected.ComposeProject, selected.ComposeFile)
	configDigest := fmt.Sprintf("sha256:%x", sha256.Sum256(data))
	config, decodeErr := decodeComposeConfig(data)
	clear(data)
	if decodeErr != nil {
		return decodeErr
	}
	defer clearComposeConfig(&config)
	selectedNames := make(map[string]bool, len(plan.Selected))
	for _, name := range plan.Selected {
		selectedNames[name] = true
	}
	if err := validateComposeConfig(config, group, selectedNames); err != nil {
		return err
	}
	evidence, ok := preflightFor(plan, target.ID, selected.ComposeProject, selected.ComposeFile)
	if !ok || evidence.ConfigDigest != configDigest {
		return errors.New("remote Compose configuration no longer matches approved preflight")
	}
	return nil
}

func targetFor(plan application.ReleasePlan, id string) (application.ReleaseTarget, bool) {
	for _, target := range plan.Targets {
		if target.ID == id {
			return target, true
		}
	}
	return application.ReleaseTarget{}, false
}

func servicesForTargetFile(plan application.ReleasePlan, targetID, project, file string) []application.ReleaseService {
	var services []application.ReleaseService
	for _, service := range plan.Services {
		if service.ComposeProject == project && service.ComposeFile == file && contains(service.Hosts, targetID) {
			services = append(services, service)
		}
	}
	return services
}

func preflightFor(plan application.ReleasePlan, targetID, project, file string) (application.ComposePreflight, bool) {
	for _, item := range plan.Preflight {
		if item.TargetID == targetID && item.Project == project && item.File == file {
			return item, true
		}
	}
	return application.ComposePreflight{}, false
}

func sortedEvidence(items []application.ComposePreflight) []application.ComposePreflight {
	result := append([]application.ComposePreflight(nil), items...)
	sort.Slice(result, func(i, j int) bool {
		if result[i].TargetID != result[j].TargetID {
			return result[i].TargetID < result[j].TargetID
		}
		if result[i].Project != result[j].Project {
			return result[i].Project < result[j].Project
		}
		return result[i].File < result[j].File
	})
	return result
}
