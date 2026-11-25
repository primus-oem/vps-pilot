package secrets

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"github.com/primus-oem/vps-pilot/core/internal/state"
	sshtransport "github.com/primus-oem/vps-pilot/core/internal/transport/ssh"
)

type Broker interface {
	Provision(context.Context, state.Host, ProvisionRequest, []byte) (ProvisionReceipt, error)
	Revoke(context.Context, state.Host, ProvisionReceipt) error
}

type ProvisionRequest struct {
	Project     string
	Environment string
	Service     string
	Name        string
	Version     string
}

type ProvisionReceipt struct {
	TargetPath string `json:"target_path"`
	OwnerMode  string `json:"owner_mode"`
	Version    string `json:"version"`
	Digest     string `json:"digest"`
}

type SSHBroker struct {
	manager *sshtransport.Manager
}

func NewSSHBroker(manager *sshtransport.Manager) *SSHBroker {
	return &SSHBroker{manager: manager}
}

func (b *SSHBroker) Provision(ctx context.Context, host state.Host, request ProvisionRequest, value []byte) (receipt ProvisionReceipt, err error) {
	if b == nil || b.manager == nil {
		return receipt, errors.New("secret broker is not configured")
	}
	if err := request.validate(); err != nil {
		return receipt, err
	}
	if len(value) == 0 || len(value) > 1024*1024 {
		clear(value)
		return receipt, errors.New("secret value must contain 1 MiB or less")
	}
	timeout := contextTimeout(host)
	connectCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	client, err := b.manager.Connect(connectCtx, sshtransport.Config{
		Alias: host.SSHAlias, Host: host.Host, User: host.User, Port: host.Port,
		IdentityFiles: []string{host.IdentityFile}, KnownHostsFile: host.KnownHostsFile,
		Timeout: timeout,
	})
	if err != nil || client == nil {
		clear(value)
		return receipt, errors.New("strict SSH connection for secret provisioning failed")
	}
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		clear(value)
		return receipt, errors.New("open SFTP session for secret provisioning failed")
	}
	defer sftpClient.Close()

	root := path.Join("/srv/vps-pilot/secrets", request.Project, request.Environment)
	if err := ensureDirectory(sftpClient, root, 0700); err != nil {
		clear(value)
		return receipt, err
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		clear(value)
		clear(random)
		return receipt, errors.New("generate secret staging name failed")
	}
	suffix := hex.EncodeToString(random)
	clear(random)
	target := path.Join(root, request.Name+"."+request.Version)
	temp := path.Join(root, ".secret-"+suffix)
	file, err := sftpClient.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		clear(value)
		return receipt, errors.New("create secret staging file failed")
	}
	var closeOnce sync.Once
	closeFile := func() error {
		var closeErr error
		closeOnce.Do(func() { closeErr = file.Close() })
		return closeErr
	}
	if err := file.Chmod(0600); err != nil {
		_ = closeFile()
		_ = sftpClient.Remove(temp)
		clear(value)
		return receipt, errors.New("restrict secret staging file permissions failed")
	}
	written, err := file.Write(value)
	expected := len(value)
	clear(value)
	if err == nil && written != expected {
		err = errors.New("incomplete secret write")
	}
	if closeErr := closeFile(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = sftpClient.Remove(temp)
		return receipt, errors.New("write secret staging file failed")
	}
	if err := sftpClient.Rename(temp, target); err != nil {
		_ = sftpClient.Remove(temp)
		return receipt, errors.New("activate secret file failed")
	}
	if _, err := sftpClient.Lstat(target); err != nil {
		return receipt, errors.New("verify secret target failed")
	}
	return ProvisionReceipt{
		TargetPath: target,
		OwnerMode:  "0600",
		Version:    request.Version,
		Digest:     "sha256:" + hex.EncodeToString(secretDigest([]byte(target))),
	}, nil
}

func (b *SSHBroker) Revoke(ctx context.Context, host state.Host, receipt ProvisionReceipt) error {
	if receipt.TargetPath == "" || !path.IsAbs(receipt.TargetPath) || !safeSecretPath(receipt.TargetPath) {
		return errors.New("invalid secret revoke target")
	}
	timeout := contextTimeout(host)
	connectCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	client, err := b.manager.Connect(connectCtx, sshtransport.Config{
		Alias: host.SSHAlias, Host: host.Host, Port: host.Port, User: host.User,
		IdentityFiles: []string{host.IdentityFile}, KnownHostsFile: host.KnownHostsFile, Timeout: timeout,
	})
	if err != nil {
		return errors.New("strict SSH connection for secret revocation failed")
	}
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		return errors.New("open SFTP session for secret revocation failed")
	}
	defer sftpClient.Close()
	if err := sftpClient.Remove(receipt.TargetPath); err != nil {
		return errors.New("remove secret file failed")
	}
	return nil
}

func (r ProvisionRequest) validate() error {
	for _, value := range []string{r.Project, r.Environment, r.Service, r.Name, r.Version} {
		if value == "" || len(value) > 128 || path.Base(value) != value ||
			value != path.Clean(value) {
			return errors.New("invalid secret provisioning scope")
		}
	}
	return nil
}

func ensureDirectory(client *sftp.Client, dir string, mode os.FileMode) error {
	info, err := client.Stat(dir)
	if err == nil {
		if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
			return errors.New("secret directory is missing or has unsafe permissions")
		}
		return nil
	}
	if err := client.MkdirAll(dir); err != nil {
		return errors.New("create secret directory failed")
	}
	if err := client.Chmod(dir, mode); err != nil {
		return errors.New("restrict secret directory permissions failed")
	}
	info, err = client.Stat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("secret directory permissions could not be verified")
	}
	return nil
}

func safeSecretPath(value string) bool {
	return path.Clean(value) == value && len(value) >= len("/srv/vps-pilot/secrets/") &&
		value[:len("/srv/vps-pilot/secrets/")] == "/srv/vps-pilot/secrets/"
}

func secretDigest(value []byte) []byte {
	sum := sha256.Sum256(value)
	return sum[:]
}

func contextTimeout(host state.Host) time.Duration {
	seconds := host.TimeoutSeconds
	if seconds <= 0 {
		seconds = 10
	}
	return time.Duration(seconds) * time.Second
}
