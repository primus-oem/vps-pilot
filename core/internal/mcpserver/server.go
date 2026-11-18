package mcpserver

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type capabilitiesOutput struct {
	Status           string   `json:"status"`
	Capabilities     []string `json:"capabilities"`
	MutationsEnabled bool     `json:"mutations_enabled"`
}

func Run(ctx context.Context) error {
	server := mcp.NewServer(&mcp.Implementation{Name: "vps-pilot", Version: "0.1.0-dev"}, nil)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_policy_capabilities",
		Description: "Reports the operations currently enabled by this local core.",
	}, policyCapabilities)
	return server.Run(ctx, &mcp.StdioTransport{})
}

func policyCapabilities(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, capabilitiesOutput, error) {
	return nil, capabilitiesOutput{
		Status:           "ok",
		Capabilities:     []string{},
		MutationsEnabled: false,
	}, nil
}
