package inventory

import (
	"strings"
	"testing"
)

func TestSanitizeRemovesControlsAndSecrets(t *testing.T) {
	input := []byte("ok\x1b[31m password=super-secret\nTOKEN: abc123")
	output := Sanitize(input)
	if strings.Contains(output, "\x1b") || strings.Contains(output, "super-secret") || strings.Contains(output, "abc123") {
		t.Fatalf("unsafe output leaked: %q", output)
	}
	if !strings.Contains(output, "[REDACTED]") {
		t.Fatalf("expected redaction marker: %q", output)
	}
}

func TestSanitizeTruncatesLargeOutput(t *testing.T) {
	output := Sanitize([]byte(strings.Repeat("x", 5000)))
	if len(output) > 4120 || !strings.Contains(output, "[truncated]") {
		t.Fatalf("unexpected truncation: %d", len(output))
	}
}
