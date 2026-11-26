package application

import (
	"reflect"
	"sort"
	"strings"
)

func CompareReleasePlans(previous, current ReleasePlan) ReleaseDiff {
	diff := ReleaseDiff{Status: "changed", BaselineDigest: previous.Digest, Changes: []ReleaseChange{}}
	if previous.Application != current.Application || previous.Environment != current.Environment ||
		!HasValidDigest(previous) || !HasValidDigest(current) {
		diff.Status = "baseline_unavailable"
		diff.BaselineDigest = ""
		return diff
	}
	if previous.ManifestDigest != current.ManifestDigest {
		diff.Changes = append(diff.Changes, ReleaseChange{
			Resource: "application:" + current.Application, Action: "updated", Fields: []string{"manifest_digest"},
		})
	}
	if strings.Join(previous.Selected, "\x00") != strings.Join(current.Selected, "\x00") {
		diff.Changes = append(diff.Changes, ReleaseChange{
			Resource: "release_scope", Action: "updated", Fields: []string{"selected_services"},
		})
	}
	if !reflect.DeepEqual(comparisonRisk(previous.Risk), comparisonRisk(current.Risk)) {
		diff.Changes = append(diff.Changes, ReleaseChange{
			Resource: "release_policy", Action: "updated", Fields: []string{"risk"},
		})
	}
	diff.Changes = append(diff.Changes, compareServices(previous.Services, current.Services)...)
	diff.Changes = append(diff.Changes, compareTargets(previous.Targets, current.Targets)...)
	sort.Slice(diff.Changes, func(i, j int) bool {
		if diff.Changes[i].Resource != diff.Changes[j].Resource {
			return diff.Changes[i].Resource < diff.Changes[j].Resource
		}
		return diff.Changes[i].Action < diff.Changes[j].Action
	})
	if len(diff.Changes) == 0 {
		diff.Status = "unchanged"
	}
	return diff
}

func compareServices(previous, current []ReleaseService) []ReleaseChange {
	oldServices := make(map[string]ReleaseService, len(previous))
	newServices := make(map[string]ReleaseService, len(current))
	for _, service := range previous {
		oldServices[service.Name] = service
	}
	for _, service := range current {
		newServices[service.Name] = service
	}
	changes := make([]ReleaseChange, 0)
	for name, currentService := range newServices {
		oldService, ok := oldServices[name]
		if !ok {
			changes = append(changes, ReleaseChange{Resource: "service:" + name, Action: "added"})
			continue
		}
		fields := compareServiceFields(oldService, currentService)
		if len(fields) > 0 {
			sort.Strings(fields)
			changes = append(changes, ReleaseChange{Resource: "service:" + name, Action: "updated", Fields: fields})
		}
	}
	for name := range oldServices {
		if _, ok := newServices[name]; !ok {
			changes = append(changes, ReleaseChange{Resource: "service:" + name, Action: "removed"})
		}
	}
	return changes
}

func compareServiceFields(old, current ReleaseService) []string {
	fields := make([]string, 0, 9)
	if old.Image != current.Image {
		fields = append(fields, "image")
	}
	if old.Role != current.Role {
		fields = append(fields, "role")
	}
	if old.ComposeProject != current.ComposeProject || old.ComposeFile != current.ComposeFile ||
		old.ComposeService != current.ComposeService {
		fields = append(fields, "compose_mapping")
	}
	if !sameStrings(old.Hosts, current.Hosts) {
		fields = append(fields, "hosts")
	}
	if old.Stateful != current.Stateful {
		fields = append(fields, "stateful")
	}
	if old.Managed != current.Managed {
		fields = append(fields, "managed")
	}
	if !reflect.DeepEqual(old.SecretNames, current.SecretNames) {
		fields = append(fields, "secret_bindings")
	}
	if old.HealthCheck != current.HealthCheck {
		fields = append(fields, "health_check")
	}
	if !reflect.DeepEqual(old.Dependencies, current.Dependencies) {
		fields = append(fields, "dependencies")
	}
	return fields
}

func compareTargets(previous, current []ReleaseTarget) []ReleaseChange {
	oldTargets := make(map[string]ReleaseTarget, len(previous))
	newTargets := make(map[string]ReleaseTarget, len(current))
	for _, target := range previous {
		oldTargets[target.ID] = target
	}
	for _, target := range current {
		newTargets[target.ID] = target
	}
	changes := make([]ReleaseChange, 0)
	for id, target := range newTargets {
		old, ok := oldTargets[id]
		if !ok {
			changes = append(changes, ReleaseChange{Resource: "target:" + id, Action: "added"})
		} else if old.SSHAlias != target.SSHAlias || old.HostKeyRef != target.HostKeyRef ||
			old.AllowedRoot != target.AllowedRoot || old.HostIdentityDigest != target.HostIdentityDigest {
			changes = append(changes, ReleaseChange{
				Resource: "target:" + id, Action: "updated", Fields: []string{"identity"},
			})
		}
	}
	for id := range oldTargets {
		if _, ok := newTargets[id]; !ok {
			changes = append(changes, ReleaseChange{Resource: "target:" + id, Action: "removed"})
		}
	}
	return changes
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
