package application

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"reflect"
	"sort"
	"strings"
)

type ReleasePlan struct {
	Version        string             `json:"version"`
	Application    string             `json:"application"`
	Environment    string             `json:"environment"`
	ManifestDigest string             `json:"manifest_digest"`
	Selected       []string           `json:"selected_services"`
	Targets        []ReleaseTarget    `json:"targets"`
	Services       []ReleaseService   `json:"services"`
	Preflight      []ComposePreflight `json:"preflight"`
	Risk           RiskSummary        `json:"risk"`
	Diff           ReleaseDiff        `json:"diff"`
	Digest         string             `json:"digest"`
}

type RiskSummary struct {
	Level            string        `json:"level"`
	ApprovalRequired bool          `json:"approval_required"`
	Findings         []RiskFinding `json:"findings"`
}

type RiskFinding struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Service  string `json:"service,omitempty"`
}

type ReleaseDiff struct {
	Status         string          `json:"status"`
	BaselineDigest string          `json:"baseline_digest,omitempty"`
	Changes        []ReleaseChange `json:"changes"`
}

type ReleaseChange struct {
	Resource string   `json:"resource"`
	Action   string   `json:"action"`
	Fields   []string `json:"fields,omitempty"`
}

type ComposePreflight struct {
	TargetID      string `json:"target_id"`
	Project       string `json:"project"`
	File          string `json:"file"`
	ConfigDigest  string `json:"config_digest"`
	RuntimeDigest string `json:"runtime_digest"`
}

type ReleaseTarget struct {
	ID                 string `json:"id"`
	SSHAlias           string `json:"ssh_alias"`
	HostKeyRef         string `json:"host_key_ref"`
	AllowedRoot        string `json:"allowed_root"`
	HostIdentityDigest string `json:"host_identity_digest,omitempty"`
}

type ReleaseService struct {
	Name           string   `json:"name"`
	Role           string   `json:"role,omitempty"`
	Hosts          []string `json:"hosts"`
	ComposeProject string   `json:"compose_project"`
	ComposeFile    string   `json:"compose_file,omitempty"`
	ComposeService string   `json:"compose_service"`
	Image          string   `json:"image,omitempty"`
	Stateful       bool     `json:"stateful"`
	Managed        bool     `json:"managed"`
	SecretNames    []string `json:"secret_names"`
	HealthCheck    bool     `json:"health_check"`
	Dependencies   []string `json:"dependencies"`
}

func CreateReleasePlan(manifest *Manifest, environmentName string, selected []string) (ReleasePlan, error) {
	if err := Validate(manifest); err != nil {
		return ReleasePlan{}, err
	}
	environment, ok := manifest.Environments[environmentName]
	if !ok {
		return ReleasePlan{}, fmt.Errorf("unknown environment %q", environmentName)
	}
	if len(environment.Hosts) == 0 {
		return ReleasePlan{}, fmt.Errorf("environment %q has no hosts", environmentName)
	}
	if len(selected) == 0 {
		return ReleasePlan{}, errors.New("select at least one service")
	}
	if len(selected) > 256 {
		return ReleasePlan{}, errors.New("selected service count exceeds 256")
	}
	allowedHosts := make(map[string]bool, len(environment.Hosts))
	targetsByID := make(map[string]ReleaseTarget)
	for _, hostName := range environment.Hosts {
		host, exists := manifest.Hosts[hostName]
		if !exists {
			return ReleasePlan{}, fmt.Errorf("environment %q references unknown host %q", environmentName, hostName)
		}
		if host.HostKeyRef == "" {
			return ReleasePlan{}, fmt.Errorf("host %q has no hostKeyRef", hostName)
		}
		allowedHosts[hostName] = true
		targetsByID[hostName] = ReleaseTarget{
			ID: hostName, SSHAlias: host.SSHAlias, HostKeyRef: host.HostKeyRef, AllowedRoot: host.AllowedRoot,
		}
	}

	selectedSet := make(map[string]bool, len(selected))
	included := make(map[string]bool)
	var include func(string) error
	include = func(name string) error {
		service, exists := manifest.Services[name]
		if !exists {
			return fmt.Errorf("unknown service %q", name)
		}
		if included[name] {
			return nil
		}
		included[name] = true
		if len(service.Deploy.Hosts) == 0 {
			return fmt.Errorf("service %q has no explicit deployment host mapping", name)
		}
		for _, hostName := range service.Deploy.Hosts {
			if !allowedHosts[hostName] {
				return fmt.Errorf("service %q targets host %q outside environment %q", name, hostName, environmentName)
			}
			host := manifest.Hosts[hostName]
			if host.AllowedRoot == "" || service.Deploy.File == "" {
				return fmt.Errorf("service %q requires explicit allowedRoot and Compose file mapping", name)
			}
			root := path.Clean(host.AllowedRoot)
			file := path.Clean(service.Deploy.File)
			if file != root && !strings.HasPrefix(file, strings.TrimSuffix(root, "/")+"/") {
				return fmt.Errorf("service %q Compose file is outside host %q allowedRoot", name, hostName)
			}
		}
		for _, dependency := range service.DependsOn {
			if err := include(dependency); err != nil {
				return err
			}
		}
		return nil
	}
	for _, name := range selected {
		if selectedSet[name] {
			continue
		}
		selectedSet[name] = true
		if err := include(name); err != nil {
			return ReleasePlan{}, err
		}
	}
	order, err := TopologicalOrder(manifest)
	if err != nil {
		return ReleasePlan{}, err
	}
	plan := ReleasePlan{
		Version:        "v1",
		Application:    manifest.Metadata.Name,
		Environment:    environmentName,
		ManifestDigest: ManifestDigest(manifest),
		Selected:       make([]string, 0, len(selectedSet)),
		Risk: RiskSummary{
			Level:            "medium",
			ApprovalRequired: true,
			Findings:         []RiskFinding{},
		},
		Diff: ReleaseDiff{Status: "baseline_unavailable", Changes: []ReleaseChange{}},
	}
	policy := manifest.Policies[environmentName]
	for name := range selectedSet {
		plan.Selected = append(plan.Selected, name)
	}
	sort.Strings(plan.Selected)
	targetIDs := make(map[string]bool)
	for _, name := range order {
		if !included[name] {
			continue
		}
		service := manifest.Services[name]
		plan.Risk.Findings = append(plan.Risk.Findings, RiskFinding{Code: "compose_config_not_preflighted", Severity: "medium", Service: name})
		raiseRisk(&plan.Risk, "medium")
		if policy.RequireHealth && service.Health == nil {
			return ReleasePlan{}, fmt.Errorf("service %q requires a health check by policy", name)
		}
		if service.Health == nil {
			plan.Risk.Findings = append(plan.Risk.Findings, RiskFinding{Code: "health_check_missing", Severity: "medium", Service: name})
			raiseRisk(&plan.Risk, "medium")
		}
		if service.Stateful {
			plan.Risk.Findings = append(plan.Risk.Findings, RiskFinding{Code: "stateful_preflight_required", Severity: "high", Service: name})
			plan.Risk.ApprovalRequired = true
			raiseRisk(&plan.Risk, "high")
		}
		if len(service.Secrets) > 0 {
			plan.Risk.Findings = append(plan.Risk.Findings, RiskFinding{Code: "secret_binding_unverified", Severity: "high", Service: name})
			plan.Risk.ApprovalRequired = true
			raiseRisk(&plan.Risk, "high")
		}
		imageRef := ""
		if service.Image == nil && !service.Managed {
			return ReleasePlan{}, fmt.Errorf("service %q requires an immutable image reference", name)
		}
		if service.Image != nil {
			if !digestPattern.MatchString(service.Image.Digest) {
				return ReleasePlan{}, fmt.Errorf("service %q requires an immutable sha256 image digest", name)
			}
			authority := strings.SplitN(service.Image.Registry, "/", 2)[0]
			allowed := false
			for _, registry := range environment.AllowedRegistries {
				if strings.EqualFold(authority, registry) {
					allowed = true
					break
				}
			}
			if !allowed {
				return ReleasePlan{}, fmt.Errorf("service %q image registry is not allowed in environment %q", name, environmentName)
			}
			imageRef = service.Image.Registry + "@" + service.Image.Digest
			plan.Risk.Findings = append(plan.Risk.Findings, RiskFinding{Code: "image_provenance_unverified", Severity: "medium", Service: name})
			raiseRisk(&plan.Risk, "medium")
		}
		hosts := append([]string(nil), service.Deploy.Hosts...)
		sort.Strings(hosts)
		secretNames := make([]string, 0, len(service.Secrets))
		for secretName := range service.Secrets {
			secretNames = append(secretNames, secretName)
		}
		sort.Strings(secretNames)
		dependencies := append([]string(nil), service.DependsOn...)
		sort.Strings(dependencies)
		for _, host := range hosts {
			targetIDs[host] = true
		}
		plan.Services = append(plan.Services, ReleaseService{
			Name: name, Role: service.Role, Hosts: hosts,
			ComposeProject: service.Deploy.Project,
			ComposeFile:    service.Deploy.File,
			ComposeService: service.Deploy.Service,
			Image:          imageRef, Stateful: service.Stateful, Managed: service.Managed,
			SecretNames: secretNames, HealthCheck: service.Health != nil, Dependencies: dependencies,
		})
	}
	for targetID := range targetIDs {
		plan.Targets = append(plan.Targets, targetsByID[targetID])
	}
	sort.Slice(plan.Targets, func(i, j int) bool { return plan.Targets[i].ID < plan.Targets[j].ID })
	if environment.Protected {
		plan.Risk.Findings = append(plan.Risk.Findings, RiskFinding{Code: "protected_environment", Severity: "high"})
		raiseRisk(&plan.Risk, "high")
	}
	approvalSeverity := "medium"
	if environment.Protected || environment.RequireApproval || policy.RequireApproval {
		approvalSeverity = "high"
		raiseRisk(&plan.Risk, "high")
	}
	plan.Risk.Findings = append(plan.Risk.Findings, RiskFinding{Code: "out_of_band_approval_required", Severity: approvalSeverity})
	sort.Slice(plan.Risk.Findings, func(i, j int) bool {
		if plan.Risk.Findings[i].Code != plan.Risk.Findings[j].Code {
			return plan.Risk.Findings[i].Code < plan.Risk.Findings[j].Code
		}
		return plan.Risk.Findings[i].Service < plan.Risk.Findings[j].Service
	})
	if err := RefreshDigest(&plan); err != nil {
		return ReleasePlan{}, err
	}
	return plan, nil
}

func raiseRisk(summary *RiskSummary, level string) {
	if level == "high" || (level == "medium" && summary.Level == "low") {
		summary.Level = level
	}
}

func CompareReleasePlans(previous, current ReleasePlan) ReleaseDiff {
	diff := ReleaseDiff{Status: "changed", BaselineDigest: previous.Digest, Changes: []ReleaseChange{}}
	if previous.Application != current.Application || previous.Environment != current.Environment ||
		!HasValidDigest(previous) || !HasValidDigest(current) {
		diff.Status = "baseline_unavailable"
		diff.BaselineDigest = ""
		return diff
	}
	if previous.ManifestDigest != current.ManifestDigest {
		diff.Changes = append(diff.Changes, ReleaseChange{Resource: "application:" + current.Application, Action: "updated", Fields: []string{"manifest_digest"}})
	}
	if strings.Join(previous.Selected, "\x00") != strings.Join(current.Selected, "\x00") {
		diff.Changes = append(diff.Changes, ReleaseChange{Resource: "release_scope", Action: "updated", Fields: []string{"selected_services"}})
	}
	if !reflect.DeepEqual(comparisonRisk(previous.Risk), comparisonRisk(current.Risk)) {
		diff.Changes = append(diff.Changes, ReleaseChange{Resource: "release_policy", Action: "updated", Fields: []string{"risk"}})
	}

	oldServices := make(map[string]ReleaseService, len(previous.Services))
	newServices := make(map[string]ReleaseService, len(current.Services))
	for _, service := range previous.Services {
		oldServices[service.Name] = service
	}
	for _, service := range current.Services {
		newServices[service.Name] = service
	}
	for name, currentService := range newServices {
		oldService, ok := oldServices[name]
		if !ok {
			diff.Changes = append(diff.Changes, ReleaseChange{Resource: "service:" + name, Action: "added"})
			continue
		}
		fields := make([]string, 0, 6)
		if oldService.Image != currentService.Image {
			fields = append(fields, "image")
		}
		if oldService.Role != currentService.Role {
			fields = append(fields, "role")
		}
		if oldService.ComposeProject != currentService.ComposeProject || oldService.ComposeFile != currentService.ComposeFile ||
			oldService.ComposeService != currentService.ComposeService {
			fields = append(fields, "compose_mapping")
		}
		if strings.Join(oldService.Hosts, "\x00") != strings.Join(currentService.Hosts, "\x00") {
			fields = append(fields, "hosts")
		}
		if oldService.Stateful != currentService.Stateful {
			fields = append(fields, "stateful")
		}
		if oldService.Managed != currentService.Managed {
			fields = append(fields, "managed")
		}
		if !reflect.DeepEqual(oldService.SecretNames, currentService.SecretNames) {
			fields = append(fields, "secret_bindings")
		}
		if oldService.HealthCheck != currentService.HealthCheck {
			fields = append(fields, "health_check")
		}
		if !reflect.DeepEqual(oldService.Dependencies, currentService.Dependencies) {
			fields = append(fields, "dependencies")
		}
		if len(fields) > 0 {
			sort.Strings(fields)
			diff.Changes = append(diff.Changes, ReleaseChange{Resource: "service:" + name, Action: "updated", Fields: fields})
		}
	}
	for name := range oldServices {
		if _, ok := newServices[name]; !ok {
			diff.Changes = append(diff.Changes, ReleaseChange{Resource: "service:" + name, Action: "removed"})
		}
	}
	oldTargets := make(map[string]ReleaseTarget, len(previous.Targets))
	newTargets := make(map[string]ReleaseTarget, len(current.Targets))
	for _, target := range previous.Targets {
		oldTargets[target.ID] = target
	}
	for _, target := range current.Targets {
		newTargets[target.ID] = target
	}
	for id, target := range newTargets {
		old, ok := oldTargets[id]
		if !ok {
			diff.Changes = append(diff.Changes, ReleaseChange{Resource: "target:" + id, Action: "added"})
		} else if old.SSHAlias != target.SSHAlias || old.HostKeyRef != target.HostKeyRef ||
			old.AllowedRoot != target.AllowedRoot || old.HostIdentityDigest != target.HostIdentityDigest {
			diff.Changes = append(diff.Changes, ReleaseChange{Resource: "target:" + id, Action: "updated", Fields: []string{"identity"}})
		}
	}
	for id := range oldTargets {
		if _, ok := newTargets[id]; !ok {
			diff.Changes = append(diff.Changes, ReleaseChange{Resource: "target:" + id, Action: "removed"})
		}
	}
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

func RefreshDigest(plan *ReleasePlan) error {
	if plan == nil {
		return errors.New("release plan is required")
	}
	plan.Digest = ""
	encoded, err := json.Marshal(plan)
	if err != nil {
		return fmt.Errorf("canonicalize release plan: %w", err)
	}
	plan.Digest = fmt.Sprintf("sha256:%x", sha256.Sum256(encoded))
	return nil
}

func ComparisonFingerprint(plan ReleasePlan) (string, error) {
	plan.Diff = ReleaseDiff{}
	plan.Preflight = nil
	plan.Digest = ""
	plan.Risk = comparisonRisk(plan.Risk)
	encoded, err := json.Marshal(plan)
	if err != nil {
		return "", fmt.Errorf("canonicalize release comparison: %w", err)
	}
	return fmt.Sprintf("sha256:%x", sha256.Sum256(encoded)), nil
}

func BindPreflight(plan *ReleasePlan, evidence []ComposePreflight) error {
	if plan == nil || len(evidence) == 0 {
		return errors.New("release plan and preflight evidence are required")
	}
	plan.Preflight = append([]ComposePreflight(nil), evidence...)
	sort.Slice(plan.Preflight, func(i, j int) bool {
		if plan.Preflight[i].TargetID != plan.Preflight[j].TargetID {
			return plan.Preflight[i].TargetID < plan.Preflight[j].TargetID
		}
		if plan.Preflight[i].Project != plan.Preflight[j].Project {
			return plan.Preflight[i].Project < plan.Preflight[j].Project
		}
		return plan.Preflight[i].File < plan.Preflight[j].File
	})
	findings := plan.Risk.Findings[:0]
	for _, finding := range plan.Risk.Findings {
		if finding.Code != "compose_config_not_preflighted" {
			findings = append(findings, finding)
		}
	}
	plan.Risk.Findings = findings
	plan.Risk.Level = "low"
	for _, finding := range findings {
		raiseRisk(&plan.Risk, finding.Severity)
	}
	return RefreshDigest(plan)
}

func comparisonRisk(summary RiskSummary) RiskSummary {
	findings := make([]RiskFinding, 0, len(summary.Findings))
	for _, finding := range summary.Findings {
		if finding.Code != "compose_config_not_preflighted" {
			findings = append(findings, finding)
		}
	}
	summary.Findings = findings
	summary.Level = "low"
	for _, finding := range findings {
		raiseRisk(&summary, finding.Severity)
	}
	return summary
}

func ManifestDigest(manifest *Manifest) string {
	encoded, _ := json.Marshal(manifest)
	return fmt.Sprintf("sha256:%x", sha256.Sum256(encoded))
}

func HasValidDigest(plan ReleasePlan) bool {
	digest := plan.Digest
	plan.Digest = ""
	encoded, err := json.Marshal(plan)
	if err != nil {
		return false
	}
	return digest == fmt.Sprintf("sha256:%x", sha256.Sum256(encoded))
}
