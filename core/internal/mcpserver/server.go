package mcpserver

import (
	"context"
	"encoding/json"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/primus-oem/vps-pilot/core/internal/application"
	"github.com/primus-oem/vps-pilot/core/internal/inventory"
	"github.com/primus-oem/vps-pilot/core/internal/state"
	sshtransport "github.com/primus-oem/vps-pilot/core/internal/transport/ssh"
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

type applicationInput struct {
	ID string `json:"id"`
}

type releasePlanInput struct {
	ID          string   `json:"id"`
	Environment string   `json:"environment"`
	Services    []string `json:"services"`
}

type applicationGraphOutput struct {
	Status string   `json:"status"`
	ID     string   `json:"id"`
	Digest string   `json:"digest"`
	Order  []string `json:"topological_order"`
	Error  string   `json:"error,omitempty"`
}

func Run(ctx context.Context, version string, store *state.Store) error {
	server := mcp.NewServer(&mcp.Implementation{Name: "vps-pilot", Version: version}, nil)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_policy_capabilities",
		Description: "Reports the operations currently enabled by this local core.",
	}, policyCapabilities)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "hosts_list",
		Description: "Lists configured SSH hosts without credentials or secret values.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input struct{}) (*mcp.CallToolResult, hostOutput, error) {
		return listHosts(ctx, req, input, store)
	})
	mcp.AddTool(server, &mcp.Tool{
		Name:        "host_connection_test",
		Description: "Tests a configured SSH host using strict known_hosts verification.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input hostConnectionInput) (*mcp.CallToolResult, hostConnectionOutput, error) {
		return testHostConnection(ctx, req, input, store)
	})
	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_host_health",
		Description: "Reads bounded host, Docker, Compose and systemd health using fixed typed operations.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input hostConnectionInput) (*mcp.CallToolResult, hostHealthOutput, error) {
		return getHostHealth(ctx, req, input, store)
	})
	mcp.AddTool(server, &mcp.Tool{
		Name:        "apps_list",
		Description: "Lists locally imported application manifests.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input struct{}) (*mcp.CallToolResult, applicationListOutput, error) {
		return listApplications(ctx, req, input, store)
	})
	mcp.AddTool(server, &mcp.Tool{
		Name:        "app_graph",
		Description: "Returns dependency-safe topological service order for an imported application.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input applicationInput) (*mcp.CallToolResult, applicationGraphOutput, error) {
		return getApplicationGraph(ctx, req, input, store)
	})
	mcp.AddTool(server, &mcp.Tool{
		Name:        "plan_application_release",
		Description: "Builds an immutable, digest-bound release plan; it does not execute changes.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input releasePlanInput) (*mcp.CallToolResult, application.ReleasePlan, error) {
		return createApplicationReleasePlan(ctx, req, input, store)
	})
	return server.Run(ctx, &mcp.StdioTransport{})
}

func policyCapabilities(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, capabilitiesOutput, error) {
	return nil, capabilitiesOutput{
		Status:           "ok",
		Capabilities:     []string{},
		MutationsEnabled: false,
	}, nil
}

func listHosts(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}, store *state.Store) (*mcp.CallToolResult, hostOutput, error) {
	hosts, err := store.ListHosts(ctx)
	if err != nil {
		return nil, hostOutput{Status: "error"}, err
	}
	summaries := make([]hostSummary, 0, len(hosts))
	for _, host := range hosts {
		summaries = append(summaries, hostSummary{
			ID: inventory.Sanitize([]byte(host.ID)), Environment: inventory.Sanitize([]byte(host.Environment)), SSHAlias: inventory.Sanitize([]byte(host.SSHAlias)),
			Host: inventory.Sanitize([]byte(host.Host)), Port: host.Port, User: inventory.Sanitize([]byte(host.User)),
			KnownHostsPinned: host.KnownHostsFile != "",
		})
	}
	return nil, hostOutput{Status: "ok", Hosts: summaries}, nil
}

func testHostConnection(ctx context.Context, _ *mcp.CallToolRequest, input hostConnectionInput, store *state.Store) (*mcp.CallToolResult, hostConnectionOutput, error) {
	host, err := store.GetHost(ctx, input.Alias)
	if err != nil {
		return nil, hostConnectionOutput{Status: "error", Alias: input.Alias, Error: "host not configured"}, nil
	}
	manager := sshtransport.NewManager()
	defer manager.Close()
	clientCtx, cancel := context.WithTimeout(ctx, time.Duration(host.TimeoutSeconds)*time.Second)
	defer cancel()
	client, err := manager.Connect(clientCtx, sshtransport.Config{
		Alias: host.SSHAlias, Host: host.Host, User: host.User, Port: host.Port,
		IdentityFiles: []string{host.IdentityFile}, KnownHostsFile: host.KnownHostsFile,
		Timeout: time.Duration(host.TimeoutSeconds) * time.Second,
	})
	if err != nil {
		return nil, hostConnectionOutput{Status: "error", Alias: host.SSHAlias, Error: sanitizeSSHError(err.Error())}, nil
	}
	if client == nil {
		return nil, hostConnectionOutput{Status: "error", Alias: host.SSHAlias, Error: "SSH connection unavailable"}, nil
	}
	return nil, hostConnectionOutput{Status: "ok", Alias: host.SSHAlias}, nil
}

func getHostHealth(ctx context.Context, _ *mcp.CallToolRequest, input hostConnectionInput, store *state.Store) (*mcp.CallToolResult, hostHealthOutput, error) {
	host, err := store.GetHost(ctx, input.Alias)
	if err != nil {
		return nil, hostHealthOutput{Status: "error", Alias: input.Alias, Error: "host not configured"}, nil
	}
	manager := sshtransport.NewManager()
	defer manager.Close()
	healthCtx, cancel := inventory.ContextWithDeadline(ctx, time.Duration(host.TimeoutSeconds)*time.Second)
	defer cancel()
	client, err := manager.Connect(healthCtx, sshtransport.Config{
		Alias: host.SSHAlias, Host: host.Host, User: host.User, Port: host.Port,
		IdentityFiles: []string{host.IdentityFile}, KnownHostsFile: host.KnownHostsFile,
		Timeout: time.Duration(host.TimeoutSeconds) * time.Second,
	})
	if err != nil {
		return nil, hostHealthOutput{Status: "error", Alias: host.SSHAlias, Error: sanitizeSSHError(err.Error())}, nil
	}
	health, err := inventory.Collect(healthCtx, client)
	if err != nil {
		return nil, hostHealthOutput{Status: "error", Alias: host.SSHAlias, Error: sanitizeSSHError(err.Error())}, nil
	}
	return nil, hostHealthOutput{Status: health.Status, Alias: host.SSHAlias, Health: health}, nil
}

func sanitizeSSHError(message string) string {
	message = inventory.Sanitize([]byte(message))
	if len(message) > 300 {
		end := 300
		for end > 0 && !utf8.RuneStart(message[end]) {
			end--
		}
		message = message[:end]
	}
	return message
}

func listApplications(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}, store *state.Store) (*mcp.CallToolResult, applicationListOutput, error) {
	apps, err := store.ListApplications(ctx)
	if err != nil {
		return nil, applicationListOutput{Status: "error"}, err
	}
	summaries := make([]applicationSummary, 0, len(apps))
	for _, app := range apps {
		summaries = append(summaries, applicationSummary{ID: app.ID, Name: app.Name, Digest: app.Digest})
	}
	return nil, applicationListOutput{Status: "ok", Apps: summaries}, nil
}

func getApplicationGraph(ctx context.Context, _ *mcp.CallToolRequest, input applicationInput, store *state.Store) (*mcp.CallToolResult, applicationGraphOutput, error) {
	app, err := store.GetApplication(ctx, input.ID)
	if err != nil {
		return nil, applicationGraphOutput{Status: "error", ID: input.ID, Error: "application not found"}, nil
	}
	var manifest application.Manifest
	if err := json.Unmarshal([]byte(app.Manifest), &manifest); err != nil {
		return nil, applicationGraphOutput{Status: "error", ID: input.ID, Error: "stored manifest is invalid"}, nil
	}
	order, err := application.TopologicalOrder(&manifest)
	if err != nil {
		return nil, applicationGraphOutput{Status: "error", ID: input.ID, Error: err.Error()}, nil
	}
	return nil, applicationGraphOutput{Status: "ok", ID: app.ID, Digest: app.Digest, Order: order}, nil
}

func createApplicationReleasePlan(ctx context.Context, _ *mcp.CallToolRequest, input releasePlanInput, store *state.Store) (*mcp.CallToolResult, application.ReleasePlan, error) {
	app, err := store.GetApplication(ctx, input.ID)
	if err != nil {
		return nil, application.ReleasePlan{}, err
	}
	var manifest application.Manifest
	if err := json.Unmarshal([]byte(app.Manifest), &manifest); err != nil {
		return nil, application.ReleasePlan{}, err
	}
	plan, err := application.CreateReleasePlan(&manifest, input.Environment, input.Services)
	if err != nil {
		return nil, application.ReleasePlan{}, err
	}
	return nil, plan, nil
}
