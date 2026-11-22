package deployment

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"github.com/primus-oem/vps-pilot/core/internal/state"
	sshtransport "github.com/primus-oem/vps-pilot/core/internal/transport/ssh"
	"golang.org/x/crypto/ssh"
)

const commandOutputLimit = 2 << 20
const remoteCommandTimeout = 5 * time.Minute

type Remote interface {
	CheckComposeFile(context.Context, state.Host, string, string) error
	ComposeConfig(context.Context, state.Host, string, string) ([]byte, error)
	ComposeStatus(context.Context, state.Host, string, string) ([]byte, error)
	ComposeUp(context.Context, state.Host, string, string, string) error
}

type SSHRemote struct {
	manager *sshtransport.Manager
}

func NewSSHRemote(manager *sshtransport.Manager) *SSHRemote {
	return &SSHRemote{manager: manager}
}

func (r *SSHRemote) CheckComposeFile(ctx context.Context, host state.Host, allowedRoot, composeFile string) error {
	client, err := r.connect(ctx, host)
	if err != nil {
		return err
	}
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		return errors.New("open SFTP preflight session")
	}
	defer sftpClient.Close()
	stopCancel := context.AfterFunc(ctx, func() { _ = sftpClient.Close() })
	defer stopCancel()

	rootInfo, err := sftpClient.Lstat(allowedRoot)
	if err != nil || !rootInfo.IsDir() {
		return errors.New("configured remote root is not a regular directory")
	}
	rootResolved, err := sftpClient.RealPath(allowedRoot)
	if err != nil || rootResolved != path.Clean(allowedRoot) {
		return errors.New("configured remote root contains a symbolic link")
	}
	fileInfo, err := sftpClient.Lstat(composeFile)
	if err != nil || !fileInfo.Mode().IsRegular() {
		return errors.New("Compose file is not a regular file")
	}
	fileResolved, err := sftpClient.RealPath(composeFile)
	if err != nil || fileResolved != path.Clean(composeFile) || !pathWithin(rootResolved, fileResolved) {
		return errors.New("Compose file resolves outside the configured remote root")
	}
	return nil
}

func (r *SSHRemote) ComposeConfig(ctx context.Context, host state.Host, project, composeFile string) ([]byte, error) {
	return r.run(ctx, host, composeBase(project, composeFile)+" config --format json")
}

func (r *SSHRemote) ComposeStatus(ctx context.Context, host state.Host, project, composeFile string) ([]byte, error) {
	return r.run(ctx, host, composeBase(project, composeFile)+" ps --format json")
}

func (r *SSHRemote) ComposeUp(ctx context.Context, host state.Host, project, composeFile, service string) error {
	output, err := r.run(ctx, host, composeBase(project, composeFile)+
		" up --detach --no-deps --pull always --wait --wait-timeout 60 "+shellQuote(service))
	clear(output)
	return err
}

func (r *SSHRemote) run(ctx context.Context, host state.Host, command string) ([]byte, error) {
	client, err := r.connect(ctx, host)
	if err != nil {
		return nil, err
	}
	session, err := client.NewSession()
	if err != nil {
		return nil, errors.New("open typed Compose operation")
	}
	defer session.Close()

	stdout := &boundedBuffer{limit: commandOutputLimit}
	stderr := &boundedBuffer{limit: commandOutputLimit}
	session.Stdout = stdout
	session.Stderr = stderr
	result := make(chan error, 1)
	go func() { result <- session.Run(command) }()
	commandCtx, cancel := context.WithTimeout(ctx, remoteCommandTimeout)
	defer cancel()
	select {
	case <-commandCtx.Done():
		_ = session.Close()
		select {
		case <-result:
		case <-time.After(time.Second):
		}
		clear(stdout.drainBytes())
		clear(stderr.drainBytes())
		return nil, errors.New("typed Compose operation timed out")
	case err := <-result:
		output, truncated := stdout.drain()
		clear(stderr.drainBytes())
		if err != nil || truncated {
			clear(output)
			return nil, errors.New("typed Compose operation failed")
		}
		return output, nil
	}
}

func (r *SSHRemote) connect(ctx context.Context, host state.Host) (*ssh.Client, error) {
	timeout := time.Duration(host.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	connectCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	client, err := r.manager.Connect(connectCtx, sshtransport.Config{
		Alias: host.SSHAlias, Host: host.Host, User: host.User, Port: host.Port,
		IdentityFiles: []string{host.IdentityFile}, KnownHostsFile: host.KnownHostsFile,
		Timeout: timeout,
	})
	if err != nil || client == nil {
		return nil, errors.New("strict SSH connection to configured target failed")
	}
	return client, nil
}

type boundedBuffer struct {
	mu        sync.Mutex
	buf       []byte
	limit     int
	truncated bool
}

func (b *boundedBuffer) Write(value []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	written := len(value)
	remaining := b.limit - len(b.buf)
	if remaining > 0 {
		if len(value) > remaining {
			value = value[:remaining]
			b.truncated = true
		}
		b.buf = append(b.buf, value...)
	} else if len(value) > 0 {
		b.truncated = true
	}
	return written, nil
}

func (b *boundedBuffer) drain() ([]byte, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	value := append([]byte(nil), b.buf...)
	truncated := b.truncated
	clear(b.buf)
	b.buf = nil
	return value, truncated
}

func (b *boundedBuffer) drainBytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	value := append([]byte(nil), b.buf...)
	clear(b.buf)
	b.buf = nil
	return value
}

func composeBase(project, composeFile string) string {
	return "docker compose --project-name " + shellQuote(project) + " --file " + shellQuote(composeFile)
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func pathWithin(root, file string) bool {
	root = path.Clean(root)
	file = path.Clean(file)
	return file == root || strings.HasPrefix(file, strings.TrimSuffix(root, "/")+"/")
}

func validateRemoteTarget(root, file string) error {
	if !path.IsAbs(root) || !path.IsAbs(file) || !pathWithin(root, file) || file == path.Clean(root) {
		return fmt.Errorf("remote Compose path is outside allowed root")
	}
	return nil
}
