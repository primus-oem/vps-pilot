package mcpserver

import (
	"context"
	"os/exec"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestStdioServerExposesPolicyCapabilities(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "vps-pilot-test", Version: "test"}, nil)
	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: exec.Command("go", "run", "../../cmd/vps-pilot", "mcp")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "get_policy_capabilities", Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatal("capabilities tool returned an error")
	}
	content, ok := result.StructuredContent.(map[string]any)
	if !ok {
		t.Fatalf("expected structured content, got %T", result.StructuredContent)
	}
	if content["status"] != "ok" || content["mutations_enabled"] != true {
		t.Fatalf("unexpected capabilities response: %#v", content)
	}
	capabilities, ok := content["capabilities"].([]any)
	if !ok || len(capabilities) != 3 {
		t.Fatalf("unexpected capability list: %#v", content["capabilities"])
	}
}

func TestStdioServerExposesDeploymentToolsWithoutExecutingUnknownPlans(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "vps-pilot-test", Version: "test"}, nil)
	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: exec.Command("go", "run", "../../cmd/vps-pilot", "mcp")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	for _, name := range []string{"preflight_application_release", "execute_approved_plan"} {
		result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: map[string]any{"digest": "unknown"}})
		if err != nil {
			t.Fatal(err)
		}
		content, ok := result.StructuredContent.(map[string]any)
		if !ok || content["status"] != "error" {
			t.Fatalf("unexpected %s response: %#v", name, result.StructuredContent)
		}
	}
}

func TestStdioServerListsHostsAndApplicationsSafely(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "vps-pilot-test", Version: "test"}, nil)
	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: exec.Command("go", "run", "../../cmd/vps-pilot", "mcp")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	for _, name := range []string{"hosts_list", "apps_list"} {
		result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: map[string]any{}})
		if err != nil {
			t.Fatal(err)
		}
		if result.IsError {
			t.Fatalf("%s returned an error", name)
		}
		content, ok := result.StructuredContent.(map[string]any)
		if !ok || content["status"] != "ok" {
			t.Fatalf("unexpected %s response: %#v", name, result.StructuredContent)
		}
	}
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "app_inventory", Arguments: map[string]any{"id": "missing"}})
	if err != nil {
		t.Fatal(err)
	}
	content, ok := result.StructuredContent.(map[string]any)
	if !ok || content["status"] != "error" {
		t.Fatalf("unexpected app_inventory response: %#v", result.StructuredContent)
	}
}
