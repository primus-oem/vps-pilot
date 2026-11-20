package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
)

type Health struct {
	Status          string         `json:"status"`
	System          string         `json:"system"`
	Uptime          string         `json:"uptime"`
	Disk            string         `json:"disk"`
	Systemd         string         `json:"systemd"`
	DockerAvailable bool           `json:"docker_available"`
	ComposeVersion  string         `json:"compose_version"`
	ComposeStacks   []ComposeStack `json:"compose_stacks"`
	Warning         string         `json:"warning,omitempty"`
}

type ComposeStack struct {
	Name        string `json:"name"`
	Status      string `json:"status"`
	ConfigFiles string `json:"config_files,omitempty"`
}

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(authorization:\s*bearer\s+)\S+`),
	regexp.MustCompile(`(?i)((?:"|')?(?:password|passwd|secret|token|api[_-]?key|authorization)(?:"|')?\s*[=:]\s*)(?:"[^"]*"|'[^']*'|[^\s,;}]+)`),
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
	buf   []byte
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	written := len(p)
	remaining := b.limit - len(b.buf)
	if remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		b.buf = append(b.buf, p...)
	}
	return written, nil
}

func Collect(ctx context.Context, client *ssh.Client) (Health, error) {
	if client == nil {
		return Health{}, errors.New("SSH client is unavailable")
	}
	health := Health{Status: "ok", ComposeStacks: []ComposeStack{}}
	var checksOK = true
	health.System, checksOK = collectFixed(ctx, client, "system", checksOK)
	health.Uptime, checksOK = collectFixed(ctx, client, "uptime", checksOK)
	health.Disk, checksOK = collectFixed(ctx, client, "disk", checksOK)
	health.Systemd, checksOK = collectFixed(ctx, client, "systemd", checksOK)
	docker, dockerOK := runFixed(ctx, client, "docker")
	health.DockerAvailable = dockerOK && docker != "" && !strings.Contains(strings.ToLower(docker), "error")
	health.ComposeVersion, checksOK = collectFixed(ctx, client, "compose-version", checksOK)
	stacks, stacksOK := runFixed(ctx, client, "compose-list")
	if stacksOK {
		if err := json.Unmarshal([]byte(stacks), &health.ComposeStacks); err != nil {
			stacksOK = false
		} else {
			if len(health.ComposeStacks) > 64 {
				health.ComposeStacks = health.ComposeStacks[:64]
			}
			for i := range health.ComposeStacks {
				health.ComposeStacks[i].Name = clip(Sanitize([]byte(health.ComposeStacks[i].Name)), 128)
				health.ComposeStacks[i].Status = clip(Sanitize([]byte(health.ComposeStacks[i].Status)), 128)
				health.ComposeStacks[i].ConfigFiles = clip(Sanitize([]byte(health.ComposeStacks[i].ConfigFiles)), 256)
			}
		}
	}
	if !stacksOK {
		health.ComposeStacks = []ComposeStack{}
	}
	if !checksOK || !dockerOK || !stacksOK {
		health.Status = "partial"
		health.Warning = "Some Docker/Compose health checks were unavailable"
	}
	return health, nil
}

func collectFixed(ctx context.Context, client *ssh.Client, operation string, checksOK bool) (string, bool) {
	value, ok := runFixed(ctx, client, operation)
	return value, checksOK && ok
}

func runFixed(ctx context.Context, client *ssh.Client, operation string) (string, bool) {
	command, ok := fixedCommands[operation]
	if !ok {
		return "", false
	}
	session, err := client.NewSession()
	if err != nil {
		return "", false
	}
	defer session.Close()
	type result struct {
		output []byte
		err    error
	}
	results := make(chan result, 1)
	stdout := &limitedBuffer{limit: 2048}
	stderr := &limitedBuffer{limit: 2048}
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
		return "", false
	case result := <-results:
		if result.err != nil {
			return Sanitize(result.output), false
		}
		return Sanitize(result.output), true
	}
}

func Sanitize(input []byte) string {
	text := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return r
		}
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Cs) {
			return -1
		}
		return r
	}, string(input))
	for _, pattern := range secretPatterns {
		text = pattern.ReplaceAllString(text, "$1[REDACTED]")
	}
	text = strings.TrimSpace(text)
	const maxBytes = 4096
	if len(text) > maxBytes {
		text = clip(text, maxBytes) + "\n[truncated]"
	}
	return text
}

func clip(text string, max int) string {
	if len(text) <= max {
		return text
	}
	for max > 0 && !utf8.RuneStart(text[max]) {
		max--
	}
	return text[:max]
}

func ContextWithDeadline(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return context.WithTimeout(ctx, timeout)
}
