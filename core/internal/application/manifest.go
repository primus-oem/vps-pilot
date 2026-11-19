package application

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type Manifest struct {
	APIVersion   string                 `yaml:"apiVersion"`
	Kind         string                 `yaml:"kind"`
	Metadata     Metadata               `yaml:"metadata"`
	Environments map[string]Environment `yaml:"environments"`
	Hosts        map[string]Host        `yaml:"hosts"`
	Services     map[string]Service     `yaml:"services"`
	Policies     map[string]Policy      `yaml:"policies"`
}

type Metadata struct {
	Name string `yaml:"name"`
}

type Environment struct {
	Protected       bool     `yaml:"protected"`
	Hosts           []string `yaml:"hosts"`
	RequireApproval bool     `yaml:"requireApproval"`
}

type Host struct {
	SSHAlias    string `yaml:"sshAlias"`
	AllowedRoot string `yaml:"allowedRoot"`
	HostKeyRef  string `yaml:"hostKeyRef"`
}

type Repository struct {
	Provider string `yaml:"provider"`
	Project  string `yaml:"project"`
}

type Deploy struct {
	Driver  string `yaml:"driver"`
	Project string `yaml:"project"`
	File    string `yaml:"file"`
	Service string `yaml:"service"`
}

type Image struct {
	Registry string `yaml:"registry"`
	Digest   string `yaml:"digest"`
}

type Health struct {
	Type           string `yaml:"type"`
	URLRef         string `yaml:"urlRef"`
	ExpectedStatus int    `yaml:"expectedStatus"`
}

type SecretRef struct {
	Ref       string `yaml:"ref"`
	Injection string `yaml:"injection"`
}

type Service struct {
	Role       string               `yaml:"role"`
	Repository *Repository          `yaml:"repository"`
	Deploy     Deploy               `yaml:"deploy"`
	Image      *Image               `yaml:"image"`
	DependsOn  []string             `yaml:"dependsOn"`
	Health     *Health              `yaml:"health"`
	Secrets    map[string]SecretRef `yaml:"secrets"`
	Managed    bool                 `yaml:"managed"`
	Stateful   bool                 `yaml:"stateful"`
}

type Policy struct {
	DenyArbitraryShell bool `yaml:"denyArbitraryShell"`
	RequireImmutable   bool `yaml:"requireImmutableImages"`
	RequireHealth      bool `yaml:"requireHealthChecks"`
	RequireApproval    bool `yaml:"requireOutOfBandApproval"`
}

func Parse(data []byte) (*Manifest, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("parse application manifest: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return nil, errors.New("manifest must contain exactly one YAML document")
	}
	if err := Validate(&manifest); err != nil {
		return nil, err
	}
	return &manifest, nil
}

var digestPattern = regexp.MustCompile(`^sha256:[a-fA-F0-9]{64}$`)
var serviceNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)
var composeNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

func Validate(manifest *Manifest) error {
	if manifest.APIVersion != "vpspilot.dev/v1alpha1" {
		return fmt.Errorf("unsupported apiVersion %q", manifest.APIVersion)
	}
	if manifest.Kind != "Application" {
		return fmt.Errorf("unsupported kind %q", manifest.Kind)
	}
	if strings.TrimSpace(manifest.Metadata.Name) == "" {
		return errors.New("metadata.name is required")
	}
	if len(manifest.Services) == 0 {
		return errors.New("at least one service is required")
	}
	for name, host := range manifest.Hosts {
		if strings.TrimSpace(host.SSHAlias) == "" {
			return fmt.Errorf("host %q requires sshAlias", name)
		}
		if host.AllowedRoot != "" && (strings.Contains(host.AllowedRoot, "..") || !strings.HasPrefix(host.AllowedRoot, "/")) {
			return fmt.Errorf("host %q has unsafe allowedRoot", name)
		}
	}
	for name, service := range manifest.Services {
		if !serviceNamePattern.MatchString(name) {
			return fmt.Errorf("invalid service name %q", name)
		}
		if service.Deploy.Driver != "compose" {
			return fmt.Errorf("service %q requires compose deployment driver", name)
		}
		if strings.TrimSpace(service.Deploy.Project) == "" || strings.TrimSpace(service.Deploy.Service) == "" {
			return fmt.Errorf("service %q requires compose project and service", name)
		}
		if !composeNamePattern.MatchString(service.Deploy.Project) || !composeNamePattern.MatchString(service.Deploy.Service) {
			return fmt.Errorf("service %q has unsafe Compose project or service name", name)
		}
		if service.Deploy.File != "" && !strings.HasPrefix(service.Deploy.File, "/") {
			return fmt.Errorf("service %q compose file must be absolute", name)
		}
		if service.Image != nil && service.Image.Digest != "" && !digestPattern.MatchString(service.Image.Digest) {
			return fmt.Errorf("service %q has invalid OCI digest", name)
		}
		for _, dependency := range service.DependsOn {
			if _, ok := manifest.Services[dependency]; !ok {
				return fmt.Errorf("service %q depends on unknown service %q", name, dependency)
			}
		}
		for secretName, secret := range service.Secrets {
			if secretName == "" || secret.Ref == "" || secret.Injection != "file" {
				return fmt.Errorf("service %q has invalid secret reference %q", name, secretName)
			}
		}
	}
	if _, err := TopologicalOrder(manifest); err != nil {
		return err
	}
	return nil
}

func TopologicalOrder(manifest *Manifest) ([]string, error) {
	visited := make(map[string]uint8)
	var result []string
	var visit func(string) error
	visit = func(name string) error {
		if visited[name] == 2 {
			return nil
		}
		if visited[name] == 1 {
			return fmt.Errorf("service dependency cycle includes %q", name)
		}
		visited[name] = 1
		dependencies := append([]string(nil), manifest.Services[name].DependsOn...)
		sort.Strings(dependencies)
		for _, dependency := range dependencies {
			if err := visit(dependency); err != nil {
				return err
			}
		}
		visited[name] = 2
		result = append(result, name)
		return nil
	}
	names := make([]string, 0, len(manifest.Services))
	for name := range manifest.Services {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := visit(name); err != nil {
			return nil, err
		}
	}
	return result, nil
}
