package planning

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/primus-oem/vps-pilot/core/internal/application"
	"github.com/primus-oem/vps-pilot/core/internal/state"
	"golang.org/x/crypto/ssh/agent"
)

type Planner struct {
	store *state.Store
}

func New(store *state.Store) *Planner {
	return &Planner{store: store}
}

func (p *Planner) Create(ctx context.Context, applicationID, environment string, selected []string) (application.ReleasePlan, error) {
	stored, err := p.store.GetApplication(ctx, applicationID)
	if err != nil {
		return application.ReleasePlan{}, err
	}
	var manifest application.Manifest
	if err := json.Unmarshal([]byte(stored.Manifest), &manifest); err != nil {
		return application.ReleasePlan{}, fmt.Errorf("decode stored application manifest: %w", err)
	}
	plan, err := application.CreateReleasePlan(&manifest, environment, selected)
	if err != nil {
		return application.ReleasePlan{}, err
	}
	if err := BindHostIdentities(ctx, p.store, &plan); err != nil {
		return application.ReleasePlan{}, err
	}
	if err := application.RefreshDigest(&plan); err != nil {
		return application.ReleasePlan{}, err
	}
	coreDigest, err := application.ComparisonFingerprint(plan)
	if err != nil {
		return application.ReleasePlan{}, err
	}

	previous, err := p.store.PreviousReleasePlan(ctx, plan.Application, environment, coreDigest)
	switch {
	case err == nil:
		var baseline application.ReleasePlan
		if err := json.Unmarshal([]byte(previous.PlanJSON), &baseline); err != nil {
			return application.ReleasePlan{}, fmt.Errorf("decode stored release baseline: %w", err)
		}
		baselineCore, err := application.ComparisonFingerprint(baseline)
		if err != nil || baseline.Digest != previous.Digest || baselineCore != previous.CoreDigest || !application.HasValidDigest(baseline) {
			return application.ReleasePlan{}, errors.New("stored release baseline failed integrity validation")
		}
		plan.Diff = application.CompareReleasePlans(baseline, plan)
	case errors.Is(err, state.ErrReleasePlanNotFound):
		plan.Diff = application.ReleaseDiff{Status: "baseline_unavailable", Changes: []application.ReleaseChange{}}
	default:
		return application.ReleasePlan{}, err
	}
	if err := application.RefreshDigest(&plan); err != nil {
		return application.ReleasePlan{}, err
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		return application.ReleasePlan{}, fmt.Errorf("encode release plan: %w", err)
	}
	if err := p.store.SaveReleasePlan(ctx, state.ReleasePlanSnapshot{
		Digest: plan.Digest, CoreDigest: coreDigest, ApplicationID: plan.Application,
		Environment: plan.Environment, ManifestDigest: plan.ManifestDigest, PlanJSON: string(encoded),
	}); err != nil {
		return application.ReleasePlan{}, err
	}
	return plan, nil
}

func BindHostIdentities(ctx context.Context, store *state.Store, plan *application.ReleasePlan) error {
	for i := range plan.Targets {
		target := &plan.Targets[i]
		host, err := store.GetHost(ctx, target.SSHAlias)
		if err != nil {
			return fmt.Errorf("release target %q is not configured locally", target.ID)
		}
		if host.SSHAlias != target.SSHAlias || host.Environment != plan.Environment {
			return fmt.Errorf("release target %q does not match configured environment or SSH alias", target.ID)
		}
		digest, err := ConfiguredHostIdentityDigest(host)
		if err != nil {
			return fmt.Errorf("release target %q has no safe SSH identity binding: %w", target.ID, err)
		}
		target.HostIdentityDigest = digest
	}
	return nil
}

func VerifyHostIdentities(ctx context.Context, store *state.Store, plan application.ReleasePlan) error {
	current := plan
	if err := BindHostIdentities(ctx, store, &current); err != nil {
		return err
	}
	if len(current.Targets) != len(plan.Targets) {
		return errors.New("release target set changed")
	}
	for i := range current.Targets {
		if current.Targets[i] != plan.Targets[i] {
			return fmt.Errorf("release target %q SSH identity changed after planning", plan.Targets[i].ID)
		}
	}
	return nil
}

func ConfiguredHostIdentityDigest(host state.Host) (string, error) {
	knownHostsDigest, err := HostKeySetDigest(host.KnownHostsFile)
	if err != nil {
		return "", err
	}
	identityPath := strings.TrimSpace(host.IdentityFile)
	identityDigest := ""
	if identityPath != "" {
		identityDigest, err = regularFileDigest(identityPath)
		if err != nil {
			return "", fmt.Errorf("inspect SSH identity: %w", err)
		}
	}
	agentPath := strings.TrimSpace(os.Getenv("SSH_AUTH_SOCK"))
	agentDigest := ""
	if agentPath != "" {
		agentDigest, err = sshAgentIdentityDigest(agentPath)
		if err != nil && identityPath == "" {
			return "", err
		}
		if err != nil {
			agentDigest = "unavailable:" + agentPath
		}
	}
	if identityPath == "" && agentDigest == "" {
		return "", errors.New("no configured SSH identity")
	}
	value := struct {
		Alias            string `json:"alias"`
		Host             string `json:"host"`
		Port             int    `json:"port"`
		User             string `json:"user"`
		Environment      string `json:"environment"`
		IdentityPath     string `json:"identity_path"`
		IdentityDigest   string `json:"identity_digest"`
		AgentPath        string `json:"agent_path"`
		AgentKeyDigest   string `json:"agent_key_digest"`
		KnownHostsPath   string `json:"known_hosts_path"`
		KnownHostsDigest string `json:"known_hosts_digest"`
	}{
		host.SSHAlias, host.Host, host.Port, host.User, host.Environment,
		identityPath, identityDigest, agentPath, agentDigest, host.KnownHostsFile, knownHostsDigest,
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("canonicalize SSH target identity: %w", err)
	}
	return fmt.Sprintf("sha256:%x", sha256.Sum256(encoded)), nil
}

func HostKeySetDigest(filePath string) (string, error) {
	filePath = strings.TrimSpace(filePath)
	if filePath == "~" || strings.HasPrefix(filePath, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve known_hosts path: %w", err)
		}
		filePath = filepath.Join(home, strings.TrimPrefix(filePath, "~/"))
	}
	info, err := os.Lstat(filePath)
	if err != nil {
		return "", fmt.Errorf("inspect known_hosts: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", errors.New("known_hosts must be a regular non-symlink file")
	}
	if info.Size() == 0 || info.Size() > 1<<20 {
		return "", errors.New("known_hosts must contain 1 byte to 1 MiB")
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("read known_hosts: %w", err)
	}
	return fmt.Sprintf("sha256:%x", sha256.Sum256(data)), nil
}

func regularFileDigest(filePath string) (string, error) {
	filePath = strings.TrimSpace(filePath)
	if filePath == "~" || strings.HasPrefix(filePath, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve SSH identity path: %w", err)
		}
		filePath = filepath.Join(home, strings.TrimPrefix(filePath, "~/"))
	}
	info, err := os.Lstat(filePath)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", errors.New("SSH identity must be a regular non-symlink file")
	}
	if info.Size() == 0 || info.Size() > 1<<20 {
		return "", errors.New("SSH identity must contain 1 byte to 1 MiB")
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("sha256:%x", sha256.Sum256(data)), nil
}

func sshAgentIdentityDigest(socket string) (string, error) {
	connection, err := net.DialTimeout("unix", socket, 2*time.Second)
	if err != nil {
		return "", fmt.Errorf("inspect ssh-agent identities: %w", err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return "", fmt.Errorf("set ssh-agent inspection deadline: %w", err)
	}
	signers, err := agent.NewClient(connection).List()
	if err != nil {
		return "", fmt.Errorf("list ssh-agent identities: %w", err)
	}
	fingerprints := make([]string, 0, len(signers))
	for _, key := range signers {
		fingerprints = append(fingerprints, key.Type()+":"+fmt.Sprintf("%x", sha256.Sum256(key.Marshal())))
	}
	sort.Strings(fingerprints)
	encoded, err := json.Marshal(fingerprints)
	if err != nil {
		return "", fmt.Errorf("canonicalize ssh-agent identities: %w", err)
	}
	return fmt.Sprintf("sha256:%x", sha256.Sum256(encoded)), nil
}
