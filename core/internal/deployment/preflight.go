package deployment

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

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

func decodeComposeConfig(data []byte) (composeConfig, error) {
	var config composeConfig
	if err := json.Unmarshal(data, &config); err != nil {
		clearComposeConfig(&config)
		return composeConfig{}, errors.New("remote Compose configuration is not valid bounded JSON")
	}
	if len(config.Services) == 0 {
		clearComposeConfig(&config)
		return composeConfig{}, errors.New("remote Compose configuration contains no services")
	}
	return config, nil
}

func validateComposeConfig(config composeConfig, services []application.ReleaseService, selected map[string]bool) error {
	for _, planned := range services {
		configured, ok := config.Services[planned.ComposeService]
		if !ok {
			return fmt.Errorf("Compose service %q is missing from remote configuration", planned.Name)
		}
		if planned.Image != "" && configured.Image != planned.Image {
			return fmt.Errorf("Compose service %q image does not match the immutable release plan", planned.Name)
		}
		if !selected[planned.Name] {
			continue
		}
		if planned.Stateful || planned.Managed {
			return fmt.Errorf("service %q requires a separate stateful deployment workflow", planned.Name)
		}
		if len(planned.SecretNames) > 0 || len(configured.Secrets) > 0 {
			return fmt.Errorf("service %q requires the unavailable secret broker workflow", planned.Name)
		}
		if hasEnvironmentEntries(configured.Environment) {
			return fmt.Errorf("service %q has unclassified environment values; deployment is denied", planned.Name)
		}
		if planned.Image == "" || !planned.HealthCheck || !hasEffectiveHealthcheck(configured.Healthcheck) {
			return fmt.Errorf("service %q requires an immutable image and configured health check", planned.Name)
		}
		if !isEmptyJSON(configured.Build) || configured.Privileged ||
			strings.EqualFold(configured.NetworkMode, "host") ||
			strings.EqualFold(configured.PID, "host") || strings.EqualFold(configured.IPC, "host") ||
			len(configured.CapAdd) > 0 || len(configured.Devices) > 0 || len(configured.Ports) > 0 {
			return fmt.Errorf("service %q uses a Compose capability outside the safe deployment policy", planned.Name)
		}
		for _, volume := range configured.Volumes {
			if strings.EqualFold(volume.Type, "bind") {
				return fmt.Errorf("service %q has a host bind mount", planned.Name)
			}
		}
		for _, option := range configured.SecurityOpt {
			if strings.Contains(strings.ToLower(option), "unconfined") || strings.Contains(strings.ToLower(option), "label:disable") {
				return fmt.Errorf("service %q relaxes container security options", planned.Name)
			}
		}
	}
	return nil
}

func validateDependenciesReady(services []application.ReleaseService, selected map[string]bool, statuses []composeStatus) error {
	byService := make(map[string][]composeStatus)
	for _, status := range statuses {
		byService[status.Service] = append(byService[status.Service], status)
	}
	for _, service := range services {
		if selected[service.Name] {
			continue
		}
		entries := byService[service.ComposeService]
		if len(entries) == 0 {
			return fmt.Errorf("dependency %q is not running on its target", service.Name)
		}
		for _, entry := range entries {
			if !strings.EqualFold(entry.State, "running") || !strings.EqualFold(entry.Health, "healthy") {
				return fmt.Errorf("dependency %q is not healthy", service.Name)
			}
		}
	}
	return nil
}

func parseComposeStatus(data []byte) ([]composeStatus, error) {
	var statuses []composeStatus
	if err := json.Unmarshal(data, &statuses); err == nil {
		return statuses, nil
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), commandOutputLimit)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var status composeStatus
		if err := json.Unmarshal(line, &status); err != nil {
			return nil, errors.New("remote Compose status is not valid bounded JSON")
		}
		statuses = append(statuses, status)
	}
	if err := scanner.Err(); err != nil {
		return nil, errors.New("remote Compose status exceeded its output limit")
	}
	return statuses, nil
}

func composeRuntimeDigest(statuses []composeStatus) (string, error) {
	sort.Slice(statuses, func(i, j int) bool {
		if statuses[i].Service != statuses[j].Service {
			return statuses[i].Service < statuses[j].Service
		}
		if statuses[i].State != statuses[j].State {
			return statuses[i].State < statuses[j].State
		}
		return statuses[i].Health < statuses[j].Health
	})
	encoded, err := json.Marshal(statuses)
	if err != nil {
		return "", fmt.Errorf("canonicalize remote Compose status: %w", err)
	}
	return fmt.Sprintf("sha256:%x", sha256.Sum256(encoded)), nil
}

func isEmptyJSON(value json.RawMessage) bool {
	trimmed := bytes.TrimSpace(value)
	return len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null"))
}

func hasEnvironmentEntries(value json.RawMessage) bool {
	if isEmptyJSON(value) {
		return false
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(value, &object); err == nil {
		for _, raw := range object {
			clear(raw)
		}
		return len(object) > 0
	}
	var array []json.RawMessage
	if err := json.Unmarshal(value, &array); err == nil {
		for _, raw := range array {
			clear(raw)
		}
		return len(array) > 0
	}
	return true
}

func hasEffectiveHealthcheck(value json.RawMessage) bool {
	return !isEmptyJSON(value)
}

func clearComposeConfig(config *composeConfig) {
	for key, service := range config.Services {
		clear(service.Build)
		clear(service.Healthcheck)
		clear(service.Environment)
		for i := range service.Devices {
			clear(service.Devices[i])
		}
		for i := range service.Ports {
			clear(service.Ports[i])
		}
		for i := range service.Secrets {
			clear(service.Secrets[i])
		}
		config.Services[key] = service
	}
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
