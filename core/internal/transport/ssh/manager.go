package ssh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

type Config struct {
	Alias          string
	Host           string
	User           string
	Port           int
	IdentityFiles  []string
	KnownHostsFile string
	Timeout        time.Duration
}

type Manager struct {
	mu      sync.Mutex
	clients map[string]*ssh.Client
}

func ResolveAlias(alias string) (Config, error) {
	alias = strings.TrimSpace(alias)
	if alias == "" {
		return Config{}, errors.New("SSH alias is required")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return Config{}, fmt.Errorf("resolve SSH config: %w", err)
	}
	data, err := os.ReadFile(filepath.Join(home, ".ssh", "config"))
	if err != nil {
		return Config{}, fmt.Errorf("read OpenSSH config: %w", err)
	}

	config := Config{Alias: alias, Port: 22}
	found := false
	lines := strings.Split(string(data), "\n")
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		key := strings.ToLower(fields[0])
		if key == "host" {
			found = false
			for _, name := range fields[1:] {
				if name == alias {
					found = true
					break
				}
			}
			continue
		}
		if !found || len(fields) < 2 {
			continue
		}
		value := strings.Trim(strings.Join(fields[1:], " "), "\"")
		switch key {
		case "hostname":
			config.Host = value
		case "user":
			config.User = value
		case "port":
			fmt.Sscanf(value, "%d", &config.Port)
		case "identityfile":
			config.IdentityFiles = append(config.IdentityFiles, expandPath(value))
		}
	}
	if config.Host == "" {
		config.Host = alias
	}
	config.KnownHostsFile = filepath.Join(home, ".ssh", "known_hosts")
	return config, nil
}

func NewManager() *Manager {
	return &Manager{clients: make(map[string]*ssh.Client)}
}

func (m *Manager) Connect(ctx context.Context, cfg Config) (*ssh.Client, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	m.mu.Lock()
	if client := m.clients[cfg.Alias]; client != nil {
		m.mu.Unlock()
		return client, nil
	}
	m.mu.Unlock()

	auth, err := authMethods(cfg.IdentityFiles)
	if err != nil {
		return nil, err
	}
	callback, err := knownhosts.New(expandPath(cfg.KnownHostsFile))
	if err != nil {
		return nil, fmt.Errorf("load known_hosts: %w", err)
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	dialer := &net.Dialer{Timeout: timeout}
	address := net.JoinHostPort(cfg.Host, fmt.Sprintf("%d", cfg.Port))
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("dial SSH host %q: %w", cfg.Alias, err)
	}

	deadline, ok := ctx.Deadline()
	if ok {
		_ = conn.SetDeadline(deadline)
	}
	clientConn, channels, requests, err := ssh.NewClientConn(conn, address, &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            auth,
		HostKeyCallback: callback,
		Timeout:         timeout,
	})
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("establish SSH connection to %q: %w", cfg.Alias, err)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = clientConn.Close()
		return nil, fmt.Errorf("clear SSH deadline: %w", err)
	}

	client := ssh.NewClient(clientConn, channels, requests)
	m.mu.Lock()
	m.clients[cfg.Alias] = client
	m.mu.Unlock()
	return client, nil
}

func (m *Manager) OpenSFTP(ctx context.Context, cfg Config) (*sftp.Client, error) {
	client, err := m.Connect(ctx, cfg)
	if err != nil {
		return nil, err
	}
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		return nil, fmt.Errorf("open SFTP session: %w", err)
	}
	return sftpClient, nil
}

func (m *Manager) Close() error {
	m.mu.Lock()
	clients := m.clients
	m.clients = make(map[string]*ssh.Client)
	m.mu.Unlock()

	var result error
	for _, client := range clients {
		if err := client.Close(); err != nil {
			result = errors.Join(result, err)
		}
	}
	return result
}

func validateConfig(cfg Config) error {
	if strings.TrimSpace(cfg.Alias) == "" {
		return errors.New("SSH alias is required")
	}
	if strings.TrimSpace(cfg.Host) == "" {
		return errors.New("SSH host is required")
	}
	if strings.TrimSpace(cfg.User) == "" {
		return errors.New("SSH user is required")
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return errors.New("SSH port must be between 1 and 65535")
	}
	if strings.TrimSpace(cfg.KnownHostsFile) == "" {
		return errors.New("known_hosts file is required")
	}
	info, err := os.Lstat(expandPath(cfg.KnownHostsFile))
	if err != nil {
		return fmt.Errorf("inspect known_hosts: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("known_hosts must not be a symlink")
	}
	if !info.Mode().IsRegular() {
		return errors.New("known_hosts must be a regular file")
	}
	return nil
}

func expandPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "~" || strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			if path == "~" {
				return home
			}
			return filepath.Join(home, strings.TrimPrefix(path, "~/"))
		}
	}
	return path
}

func authMethods(identityFiles []string) ([]ssh.AuthMethod, error) {
	methods := make([]ssh.AuthMethod, 0, len(identityFiles)+1)
	for _, identityFile := range identityFiles {
		path := expandPath(strings.TrimSpace(identityFile))
		if path == "" {
			continue
		}
		key, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read SSH identity %q: %w", path, err)
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("parse SSH identity %q: %w", path, err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}

	if socket := strings.TrimSpace(os.Getenv("SSH_AUTH_SOCK")); socket != "" {
		conn, err := net.Dial("unix", socket)
		if err == nil {
			agentClient := agent.NewClient(conn)
			methods = append(methods, ssh.PublicKeysCallback(agentClient.Signers))
		}
	}
	if len(methods) == 0 {
		return nil, errors.New("no SSH identity or usable ssh-agent available")
	}
	return methods, nil
}
