package application

import (
	"fmt"
	"net/url"
	"sort"
)

type Inventory struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Digest       string                 `json:"digest"`
	Environments []InventoryEnvironment `json:"environments"`
	Services     []InventoryService     `json:"services"`
}

type InventoryEnvironment struct {
	Name      string   `json:"name"`
	Protected bool     `json:"protected"`
	Hosts     []string `json:"hosts"`
}

type InventoryService struct {
	Name           string                   `json:"name"`
	Role           string                   `json:"role,omitempty"`
	Repository     string                   `json:"repository,omitempty"`
	Hosts          []string                 `json:"hosts"`
	ComposeProject string                   `json:"compose_project"`
	ComposeService string                   `json:"compose_service"`
	Dependencies   []string                 `json:"dependencies"`
	Secrets        []InventorySecretBinding `json:"secret_bindings"`
}

type InventorySecretBinding struct {
	Name   string `json:"name"`
	Source string `json:"source"`
	Status string `json:"status"`
}

func BuildInventory(manifest *Manifest, digest string) (Inventory, error) {
	if err := Validate(manifest); err != nil {
		return Inventory{}, err
	}
	order, err := TopologicalOrder(manifest)
	if err != nil {
		return Inventory{}, err
	}
	inventory := Inventory{
		ID:           manifest.Metadata.Name,
		Name:         manifest.Metadata.Name,
		Digest:       digest,
		Environments: make([]InventoryEnvironment, 0, len(manifest.Environments)),
		Services:     make([]InventoryService, 0, len(order)),
	}
	environmentNames := make([]string, 0, len(manifest.Environments))
	for name := range manifest.Environments {
		environmentNames = append(environmentNames, name)
	}
	sort.Strings(environmentNames)
	for _, name := range environmentNames {
		environment := manifest.Environments[name]
		hosts := append([]string(nil), environment.Hosts...)
		sort.Strings(hosts)
		inventory.Environments = append(inventory.Environments, InventoryEnvironment{
			Name: name, Protected: environment.Protected, Hosts: hosts,
		})
	}
	for _, name := range order {
		service := manifest.Services[name]
		hosts := append([]string(nil), service.Deploy.Hosts...)
		dependencies := append([]string(nil), service.DependsOn...)
		sort.Strings(hosts)
		sort.Strings(dependencies)
		repository := ""
		if service.Repository != nil {
			repository = service.Repository.Project
		}
		bindings := make([]InventorySecretBinding, 0, len(service.Secrets))
		secretNames := make([]string, 0, len(service.Secrets))
		for secretName := range service.Secrets {
			secretNames = append(secretNames, secretName)
		}
		sort.Strings(secretNames)
		for _, secretName := range secretNames {
			reference, err := url.Parse(service.Secrets[secretName].Ref)
			if err != nil {
				return Inventory{}, fmt.Errorf("parse secret reference for service %q: %w", name, err)
			}
			bindings = append(bindings, InventorySecretBinding{
				Name: secretName, Source: reference.Scheme, Status: "configured_unverified",
			})
		}
		inventory.Services = append(inventory.Services, InventoryService{
			Name: name, Role: service.Role, Repository: repository, Hosts: hosts,
			ComposeProject: service.Deploy.Project, ComposeService: service.Deploy.Service,
			Dependencies: dependencies, Secrets: bindings,
		})
	}
	return inventory, nil
}
