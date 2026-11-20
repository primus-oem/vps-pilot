package inventory

import (
	"strings"
	"testing"
)

func TestSanitizeRemovesControlsAndSecrets(t *testing.T) {
	input := []byte("ok\x1b[31m password=\"long secret\"\nTOKEN: abc123\nAuthorization: Bearer abc.bearer.token\n\u202e")
	output := Sanitize(input)
	for _, secret := range []string{"long secret", "abc123", "abc.bearer.token", "\x1b", "\u202e"} {
		if strings.Contains(output, secret) {
			t.Fatalf("unsafe output leaked: %q", output)
		}
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
