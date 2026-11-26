package deployment

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/primus-oem/vps-pilot/core/internal/application"
)

type composeConfig struct {
	Services map[string]composeConfigService `json:"services"`
}

type composeConfigService struct {
	Image       string            `json:"image"`
	Build       json.RawMessage   `json:"build"`
	Privileged  bool              `json:"privileged"`
	NetworkMode string            `json:"network_mode"`
	PID         string            `json:"pid"`
	IPC         string            `json:"ipc"`
	CapAdd      []string          `json:"cap_add"`
	Devices     []json.RawMessage `json:"devices"`
	Volumes     []struct {
		Type string `json:"type"`
	} `json:"volumes"`
	Ports       []json.RawMessage `json:"ports"`
	Secrets     []json.RawMessage `json:"secrets"`
	Healthcheck json.RawMessage   `json:"healthcheck"`
	SecurityOpt []string          `json:"security_opt"`
	Environment json.RawMessage   `json:"environment"`
}

type composeStatus struct {
	Service string `json:"Service"`
	State   string `json:"State"`
	Health  string `json:"Health"`
}

type composeGroup struct {
	target   application.ReleaseTarget
	project  string
	file     string
	services []application.ReleaseService
}

func (e *Executor) inspectPlan(ctx context.Context, plan application.ReleasePlan, beforeCommand func() error) ([]application.ComposePreflight, error) {
	groups := groupsFor(plan)
	if len(groups) == 0 {
		return nil, errors.New("release plan contains no Compose targets")
	}
	selected := make(map[string]bool, len(plan.Selected))
	for _, name := range plan.Selected {
		selected[name] = true
	}
	evidence := make([]application.ComposePreflight, 0, len(groups))
	for _, group := range groups {
		host, err := e.store.GetHost(ctx, group.target.SSHAlias)
		if err != nil {
			return nil, errors.New("configured SSH target is unavailable")
		}
		if err := validateRemoteTarget(group.target.AllowedRoot, group.file); err != nil {
			return nil, err
		}
		if beforeCommand != nil {
			if err := beforeCommand(); err != nil {
				return nil, err
			}
		}
		if err := e.remote.CheckComposeFile(ctx, host, group.target.AllowedRoot, group.file); err != nil {
			return nil, err
		}
		if beforeCommand != nil {
			if err := beforeCommand(); err != nil {
				return nil, err
			}
		}
		configData, err := e.remote.ComposeConfig(ctx, host, group.project, group.file)
		if err != nil {
			return nil, errors.New("remote Compose configuration preflight failed")
		}
		configDigest := fmt.Sprintf("sha256:%x", sha256.Sum256(configData))
		config, err := decodeComposeConfig(configData)
		clear(configData)
		if err != nil {
			return nil, err
		}
		if err := validateComposeConfig(config, group.services, selected); err != nil {
			clearComposeConfig(&config)
			return nil, err
		}
		clearComposeConfig(&config)
		if beforeCommand != nil {
			if err := beforeCommand(); err != nil {
				return nil, err
			}
		}
		statusData, err := e.remote.ComposeStatus(ctx, host, group.project, group.file)
		if err != nil {
			return nil, errors.New("remote Compose service status is unavailable")
		}
		statuses, err := parseComposeStatus(statusData)
		clear(statusData)
		if err != nil {
			return nil, err
		}
		if err := validateDependenciesReady(group.services, selected, statuses); err != nil {
			return nil, err
		}
		runtimeDigest, err := composeRuntimeDigest(statuses)
		if err != nil {
			return nil, err
		}
		evidence = append(evidence, application.ComposePreflight{
			TargetID: group.target.ID, Project: group.project, File: group.file,
			ConfigDigest: configDigest, RuntimeDigest: runtimeDigest,
		})
	}
	return evidence, nil
}

func groupsFor(plan application.ReleasePlan) []composeGroup {
	groups := make(map[string]*composeGroup)
	for _, target := range plan.Targets {
		for _, service := range plan.Services {
			if !contains(service.Hosts, target.ID) {
				continue
			}
			key := target.ID + "\x00" + service.ComposeProject + "\x00" + service.ComposeFile
			group := groups[key]
			if group == nil {
				group = &composeGroup{target: target, project: service.ComposeProject, file: service.ComposeFile}
				groups[key] = group
			}
			group.services = append(group.services, service)
		}
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]composeGroup, 0, len(keys))
	for _, key := range keys {
		result = append(result, *groups[key])
	}
	return result
}
