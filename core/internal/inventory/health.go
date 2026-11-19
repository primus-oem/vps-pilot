package inventory

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

type Health struct {
	Status          string `json:"status"`
	System          string `json:"system"`
	Uptime          string `json:"uptime"`
	Disk            string `json:"disk"`
	Systemd         string `json:"systemd"`
	DockerAvailable bool   `json:"docker_available"`
	ComposeVersion  string `json:"compose_version"`
	ComposeStacks   string `json:"compose_stacks"`
	Warning         string `json:"warning,omitempty"`
}

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(password|passwd|secret|token|api[_-]?key)\s*[=:]\s*\S+`),
	regexp.MustCompile(`(?i)(authorization:\s*bearer\s+)\S+`),
}

var fixedCommands = map[string]string{
	"system":          "uname -srm",
	"uptime":          "uptime -p",
	"disk":            "df -Pk /",
	"systemd":         "systemctl is-system-running --wait=no",
	"docker":          "docker version --format '{{.Server.Version}}'",
	"compose-version": "docker compose version --short",
	"compose-list":    "docker compose ls --format json",
}

type limitedBuffer struct {
	buf []byte
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	written := len(p)
	remaining := 4096 - len(b.buf)
	if remaining <= 0 {
		return written, nil
	}
	if len(p) > remaining {
		p = p[:remaining]
	}
	b.buf = append(b.buf, p...)
	return written, nil
}

func Collect(ctx context.Context, client *ssh.Client) (Health, error) {
	if client == nil {
		return Health{}, errors.New("SSH client is unavailable")
	}
	health := Health{Status: "ok"}
	health.System = runFixed(ctx, client, "system")
	health.Uptime = runFixed(ctx, client, "uptime")
	health.Disk = runFixed(ctx, client, "disk")
	health.Systemd = runFixed(ctx, client, "systemd")

	docker := runFixed(ctx, client, "docker")
	health.DockerAvailable = docker != "" && !strings.Contains(strings.ToLower(docker), "error")
	health.ComposeVersion = runFixed(ctx, client, "compose-version")
	health.ComposeStacks = runFixed(ctx, client, "compose-list")
	if !health.DockerAvailable {
		health.Warning = "Docker server or Docker CLI is unavailable"
	}
	return health, nil
}

func runFixed(ctx context.Context, client *ssh.Client, operation string) string {
	command, ok := fixedCommands[operation]
	if !ok {
		return ""
	}
	session, err := client.NewSession()
	if err != nil {
		return ""
	}
	defer session.Close()
	type result struct {
		output []byte
		err    error
	}
	results := make(chan result, 1)
	stdout := &limitedBuffer{}
	stderr := &limitedBuffer{}
	session.Stdout = stdout
	session.Stderr = stderr
	go func() {
		err := session.Run(command)
		output := append(stdout.buf, stderr.buf...)
		results <- result{output: output, err: err}
	}()

	select {
	case <-ctx.Done():
		_ = session.Close()
		return ""
	case result := <-results:
		_ = result.err
		return Sanitize(result.output)
	}
}

func Sanitize(input []byte) string {
	text := string(input)
	text = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return r
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, text)
	for _, pattern := range secretPatterns {
		text = pattern.ReplaceAllString(text, "$1[REDACTED]")
	}
	text = strings.TrimSpace(text)
	const maxBytes = 4096
	if len(text) > maxBytes {
		text = text[:maxBytes] + "\n[truncated]"
	}
	return text
}

func ContextWithDeadline(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return context.WithTimeout(ctx, timeout)
}
