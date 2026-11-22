package deployment

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/primus-oem/vps-pilot/core/internal/application"
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

type deploymentLock struct {
	scope string
}

func NewExecutor(store *state.Store, remote Remote) *Executor {
	return &Executor{store: store, remote: remote}
}

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
