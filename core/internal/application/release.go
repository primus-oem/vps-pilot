package application

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
)

type ReleasePlan struct {
	Version        string           `json:"version"`
	Application    string           `json:"application"`
	Environment    string           `json:"environment"`
	ManifestDigest string           `json:"manifest_digest"`
	Selected       []string         `json:"selected_services"`
	Targets        []ReleaseTarget  `json:"targets"`
	Services       []ReleaseService `json:"services"`
	Digest         string           `json:"digest"`
}

type ReleaseTarget struct {
	ID         string `json:"id"`
	SSHAlias   string `json:"ssh_alias"`
	HostKeyRef string `json:"host_key_ref"`
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
		targetsByID[hostName] = ReleaseTarget{ID: hostName, SSHAlias: host.SSHAlias, HostKeyRef: host.HostKeyRef}
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
	}
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
		}
		hosts := append([]string(nil), service.Deploy.Hosts...)
		sort.Strings(hosts)
		for _, host := range hosts {
			targetIDs[host] = true
		}
		plan.Services = append(plan.Services, ReleaseService{
			Name: name, Role: service.Role, Hosts: hosts,
			ComposeProject: service.Deploy.Project,
			ComposeFile:    service.Deploy.File,
			ComposeService: service.Deploy.Service,
			Image:          imageRef, Stateful: service.Stateful,
		})
	}
	for targetID := range targetIDs {
		plan.Targets = append(plan.Targets, targetsByID[targetID])
	}
	sort.Slice(plan.Targets, func(i, j int) bool { return plan.Targets[i].ID < plan.Targets[j].ID })
	digestInput := plan
	digestInput.Digest = ""
	encoded, err := json.Marshal(digestInput)
	if err != nil {
		return ReleasePlan{}, fmt.Errorf("canonicalize release plan: %w", err)
	}
	plan.Digest = fmt.Sprintf("sha256:%x", sha256.Sum256(encoded))
	return plan, nil
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
