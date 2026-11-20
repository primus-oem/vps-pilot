package ssh

import (
	"context"
	"crypto/sha256"
	"encoding/json"
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
	key, err := connectionKey(cfg)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	cached := m.clients[key]
	m.mu.Unlock()
	if cached != nil {
		pingCtx, cancel := context.WithTimeout(ctx, cfgTimeout(cfg))
		alive, err := clientAlive(pingCtx, cached)
		cancel()
		if err != nil {
			return nil, err
		}
		if alive {
			return cached, nil
		}
		m.mu.Lock()
		if m.clients[key] == cached {
			delete(m.clients, key)
		}
		m.mu.Unlock()
		_ = cached.Close()
	}

	auth, closeAuth, err := authMethodsWithCleanup(cfg.IdentityFiles)
	if err != nil {
		return nil, err
	}
	defer closeAuth()
	callback, err := knownhosts.New(expandPath(cfg.KnownHostsFile))
	if err != nil {
		return nil, fmt.Errorf("load known_hosts: %w", err)
	}

	timeout := cfgTimeout(cfg)
	dialer := &net.Dialer{Timeout: timeout}
	address := net.JoinHostPort(cfg.Host, fmt.Sprintf("%d", cfg.Port))
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("dial SSH host %q: %w", cfg.Alias, err)
	}

	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = conn.SetDeadline(deadline)
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancel()
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
	if previous := m.clients[key]; previous != nil {
		m.mu.Unlock()
		_ = client.Close()
		return previous, nil
	}
	m.clients[key] = client
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
	methods, cleanup, err := authMethodsWithCleanup(identityFiles)
	if cleanup != nil {
		cleanup()
	}
	return methods, err
}

func authMethodsWithCleanup(identityFiles []string) ([]ssh.AuthMethod, func(), error) {
	methods := make([]ssh.AuthMethod, 0, len(identityFiles)+1)
	var closers []net.Conn
	for _, identityFile := range identityFiles {
		path := expandPath(strings.TrimSpace(identityFile))
		if path == "" {
			continue
		}
		key, err := os.ReadFile(path)
		if err != nil {
			closeConnections(closers)
			return nil, nil, fmt.Errorf("read SSH identity %q: %w", path, err)
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			closeConnections(closers)
			return nil, nil, fmt.Errorf("parse SSH identity %q: %w", path, err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}

	if socket := strings.TrimSpace(os.Getenv("SSH_AUTH_SOCK")); socket != "" {
		conn, err := net.Dial("unix", socket)
		if err == nil {
			closers = append(closers, conn)
			agentClient := agent.NewClient(conn)
			methods = append(methods, ssh.PublicKeysCallback(agentClient.Signers))
		}
	}
	if len(methods) == 0 {
		closeConnections(closers)
		return nil, nil, errors.New("no SSH identity or usable ssh-agent available")
	}
	return methods, func() { closeConnections(closers) }, nil
}

func closeConnections(connections []net.Conn) {
	for _, connection := range connections {
		_ = connection.Close()
	}
}

func connectionKey(cfg Config) (string, error) {
	cfg.Timeout = 0
	value, err := json.Marshal(cfg)
	if err != nil {
		return "", fmt.Errorf("fingerprint SSH configuration: %w", err)
	}
	knownHosts, err := os.ReadFile(expandPath(cfg.KnownHostsFile))
	if err != nil {
		return "", fmt.Errorf("read known_hosts: %w", err)
	}
	hash := sha256.New()
	_, _ = hash.Write(value)
	_, _ = hash.Write(knownHosts)
	_, _ = hash.Write([]byte(os.Getenv("SSH_AUTH_SOCK")))
	for _, path := range cfg.IdentityFiles {
		key, err := os.ReadFile(expandPath(path))
		if err != nil {
			return "", fmt.Errorf("read SSH identity %q: %w", path, err)
		}
		_, _ = hash.Write(key)
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

func cfgTimeout(cfg Config) time.Duration {
	if cfg.Timeout <= 0 {
		return 10 * time.Second
	}
	return cfg.Timeout
}

func clientAlive(ctx context.Context, client *ssh.Client) (bool, error) {
	result := make(chan error, 1)
	go func() {
		_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
		result <- err
	}()
	select {
	case err := <-result:
		return err == nil, nil
	case <-ctx.Done():
		_ = client.Close()
		return false, ctx.Err()
	}
}
