package application

import (
	"errors"
	"fmt"
	"path"
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
