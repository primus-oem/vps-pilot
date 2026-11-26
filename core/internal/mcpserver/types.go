package mcpserver

import (
	"github.com/primus-oem/vps-pilot/core/internal/application"
	"github.com/primus-oem/vps-pilot/core/internal/inventory"
)

type capabilitiesOutput struct {
	Status           string   `json:"status"`
	Capabilities     []string `json:"capabilities"`
	MutationsEnabled bool     `json:"mutations_enabled"`
}

type hostOutput struct {
	Status string        `json:"status"`
	Hosts  []hostSummary `json:"hosts"`
}

type hostSummary struct {
	ID               string `json:"id"`
	Environment      string `json:"environment"`
	SSHAlias         string `json:"ssh_alias"`
	Host             string `json:"host"`
	Port             int    `json:"port"`
	User             string `json:"user"`
	KnownHostsPinned bool   `json:"known_hosts_pinned"`
}

type hostConnectionInput struct {
	Alias string `json:"alias"`
}

type hostConnectionOutput struct {
	Status string `json:"status"`
	Alias  string `json:"alias"`
	Error  string `json:"error,omitempty"`
}

type hostHealthOutput struct {
	Status string           `json:"status"`
	Alias  string           `json:"alias"`
	Health inventory.Health `json:"health,omitempty"`
	Error  string           `json:"error,omitempty"`
}

type applicationSummary struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Digest string `json:"digest"`
}

type applicationListOutput struct {
	Status string               `json:"status"`
	Apps   []applicationSummary `json:"applications"`
}

type applicationInventoryOutput struct {
	Status    string                `json:"status"`
	Inventory application.Inventory `json:"inventory,omitempty"`
	Error     string                `json:"error,omitempty"`
}

type secretBindingInput struct {
	Application string `json:"application,omitempty"`
	Environment string `json:"environment,omitempty"`
}

type secretBindingOutput struct {
	Status   string                 `json:"status"`
	Bindings []secretBindingSummary `json:"bindings"`
	Error    string                 `json:"error,omitempty"`
}

type secretBindingSummary struct {
	Application string `json:"application"`
	Environment string `json:"environment"`
	Host        string `json:"host"`
	Service     string `json:"service"`
	Name        string `json:"name"`
	Reference   string `json:"reference_digest"`
	Version     string `json:"version"`
	Status      string `json:"status"`
}

type applicationInput struct {
	ID string `json:"id"`
}

type releasePlanInput struct {
	ID          string   `json:"id"`
	Environment string   `json:"environment"`
	Services    []string `json:"services"`
}

type releaseDigestInput struct {
	Digest string `json:"digest"`
}

type releasePreflightOutput struct {
	Status string                  `json:"status"`
	Plan   application.ReleasePlan `json:"plan,omitempty"`
	Error  string                  `json:"error,omitempty"`
}

type deploymentOutput struct {
	Status        string   `json:"status"`
	PlanDigest    string   `json:"plan_digest"`
	CorrelationID string   `json:"correlation_id,omitempty"`
	Attempted     []string `json:"attempted_services"`
	Applied       []string `json:"applied_services"`
	Error         string   `json:"error,omitempty"`
}

type reconcileOutput struct {
	Status        string   `json:"status"`
	PlanDigest    string   `json:"plan_digest"`
	CorrelationID string   `json:"correlation_id"`
	Observed      []string `json:"observed_services"`
	Divergences   []string `json:"divergences"`
	Error         string   `json:"error,omitempty"`
}

type applicationGraphOutput struct {
	Status string   `json:"status"`
	ID     string   `json:"id"`
	Digest string   `json:"digest"`
	Order  []string `json:"topological_order"`
	Error  string   `json:"error,omitempty"`
}
