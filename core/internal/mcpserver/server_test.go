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
	command := exec.Command("go", "run", "../../cmd/vps-pilot", "mcp")
	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: command}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_policy_capabilities",
		Arguments: map[string]any{},
	})
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
	if content["status"] != "ok" || content["mutations_enabled"] != false {
		t.Fatalf("unexpected capabilities response: %#v", content)
	}
}
