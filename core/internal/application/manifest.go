package application

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
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
	Protected         bool     `yaml:"protected"`
	Hosts             []string `yaml:"hosts"`
	AllowedRegistries []string `yaml:"allowedRegistries"`
	RequireApproval   bool     `yaml:"requireApproval"`
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
	Driver  string   `yaml:"driver"`
	Project string   `yaml:"project"`
	File    string   `yaml:"file"`
	Service string   `yaml:"service"`
	Hosts   []string `yaml:"hosts"`
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

var digestPattern = regexp.MustCompile(`^sha256:[a-fA-F0-9]{64}$`)
var serviceNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)
var composeNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
var applicationNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
var hostKeyRefPattern = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,128}$`)

func Parse(data []byte) (*Manifest, error) {
	if len(data) > 1<<20 {
		return nil, errors.New("application manifest exceeds 1 MiB")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("parse application manifest: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return nil, errors.New("manifest must contain exactly one YAML document")
	} else if !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse trailing manifest data: %w", err)
	}
	if err := Validate(&manifest); err != nil {
		return nil, err
	}
	return &manifest, nil
}

func Validate(manifest *Manifest) error {
	if manifest == nil {
		return errors.New("application manifest is required")
	}
	if manifest.APIVersion != "vpspilot.dev/v1alpha1" {
		return fmt.Errorf("unsupported apiVersion %q", manifest.APIVersion)
	}
	if manifest.Kind != "Application" {
		return fmt.Errorf("unsupported kind %q", manifest.Kind)
	}
	if !applicationNamePattern.MatchString(manifest.Metadata.Name) {
		return errors.New("metadata.name must be a DNS-style identifier")
	}
	if len(manifest.Services) == 0 {
		return errors.New("at least one service is required")
	}
	if len(manifest.Services) > 512 || len(manifest.Hosts) > 128 || len(manifest.Environments) > 64 {
		return errors.New("manifest exceeds supported resource counts")
	}
	for name, host := range manifest.Hosts {
		if !serviceNamePattern.MatchString(name) || !composeNamePattern.MatchString(host.SSHAlias) {
			return fmt.Errorf("host %q requires a valid name and sshAlias", name)
		}
		if host.HostKeyRef != "" && (!hostKeyRefPattern.MatchString(host.HostKeyRef) || strings.HasPrefix(host.HostKeyRef, "/") || hasParentSegment(host.HostKeyRef)) {
			return fmt.Errorf("host %q has unsafe hostKeyRef", name)
		}
		if host.AllowedRoot != "" && (!path.IsAbs(host.AllowedRoot) || path.Clean(host.AllowedRoot) != host.AllowedRoot || hasParentSegment(host.AllowedRoot)) {
			return fmt.Errorf("host %q has unsafe allowedRoot", name)
		}
	}
	for name, environment := range manifest.Environments {
		if !serviceNamePattern.MatchString(name) {
			return fmt.Errorf("invalid environment name %q", name)
		}
		for _, hostName := range environment.Hosts {
			if _, ok := manifest.Hosts[hostName]; !ok {
				return fmt.Errorf("environment %q references unknown host %q", name, hostName)
			}
		}
		for _, registry := range environment.AllowedRegistries {
			if !registryAuthorityValid(registry) {
				return fmt.Errorf("environment %q has invalid allowed registry %q", name, registry)
			}
		}
	}
	for name := range manifest.Policies {
		if _, ok := manifest.Environments[name]; !ok {
			return fmt.Errorf("policy %q must match an environment", name)
		}
	}
	mappings := make(map[string]string)
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
		if service.Deploy.File != "" && (!path.IsAbs(service.Deploy.File) || hasParentSegment(service.Deploy.File)) {
			return fmt.Errorf("service %q has unsafe Compose file path", name)
		}
		seenHosts := make(map[string]bool)
		for _, hostName := range service.Deploy.Hosts {
			if _, ok := manifest.Hosts[hostName]; !ok {
				return fmt.Errorf("service %q references unknown host %q", name, hostName)
			}
			if seenHosts[hostName] {
				return fmt.Errorf("service %q repeats deployment host %q", name, hostName)
			}
			seenHosts[hostName] = true
			mapping := strings.Join([]string{hostName, service.Deploy.Project, service.Deploy.File, service.Deploy.Service}, "\x00")
			if previous, ok := mappings[mapping]; ok {
				return fmt.Errorf("services %q and %q map to the same Compose service", previous, name)
			}
			mappings[mapping] = name
		}
		if service.Image != nil && service.Image.Digest != "" && !digestPattern.MatchString(service.Image.Digest) {
			return fmt.Errorf("service %q has invalid OCI digest", name)
		}
		if service.Image != nil && service.Image.Registry != "" && !registryReferenceValid(service.Image.Registry) {
			return fmt.Errorf("service %q has invalid image reference", name)
		}
		for _, dependency := range service.DependsOn {
			if _, ok := manifest.Services[dependency]; !ok {
				return fmt.Errorf("service %q depends on unknown service %q", name, dependency)
			}
		}
		for secretName, secret := range service.Secrets {
			if !serviceNamePattern.MatchString(secretName) || !validSecretReference(secret.Ref) || secret.Injection != "file" {
				return fmt.Errorf("service %q has invalid secret reference %q", name, secretName)
			}
		}
	}
	_, err := TopologicalOrder(manifest)
	return err
}

func validSecretReference(reference string) bool {
	parsed, err := url.Parse(reference)
	if err != nil || (parsed.Scheme != "vault" && parsed.Scheme != "secret") || parsed.Host == "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || hasParentSegment(parsed.Path) {
		return false
	}
	return true
}

func registryAuthorityValid(authority string) bool {
	if strings.Contains(authority, "://") || strings.ContainsAny(authority, " \t\r\n@?#/") {
		return false
	}
	parsed, err := url.Parse("https://" + authority)
	return err == nil && parsed.Host != "" && parsed.User == nil && parsed.Path == "" && parsed.RawQuery == "" && parsed.Fragment == ""
}

func registryReferenceValid(reference string) bool {
	if strings.Contains(reference, "://") || strings.ContainsAny(reference, " \t\r\n@?#") {
		return false
	}
	parsed, err := url.Parse("https://" + reference)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	repository := strings.Trim(parsed.Path, "/")
	if !strings.Contains(repository, "/") {
		return false
	}
	for _, segment := range strings.Split(repository, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func hasParentSegment(value string) bool {
	for _, segment := range strings.Split(value, "/") {
		if segment == ".." {
			return true
		}
	}
	return false
}

func TopologicalOrder(manifest *Manifest) ([]string, error) {
	if manifest == nil {
		return nil, errors.New("application manifest is required")
	}
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
