package secrets

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path"
	"regexp"
	"strings"
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

func (r ProvisionRequest) TargetPath() (string, error) {
	if err := r.validate(); err != nil {
		return "", err
	}
	return path.Join("/srv/vps-pilot/secrets", r.Project, r.Environment, r.Service, r.Name+"."+r.Version), nil
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

var scopeSegmentPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$`)
var versionSegmentPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$`)

func NewSSHBroker(manager *sshtransport.Manager) *SSHBroker {
	return &SSHBroker{manager: manager}
}

func (b *SSHBroker) Provision(ctx context.Context, host state.Host, request ProvisionRequest, value []byte) (receipt ProvisionReceipt, err error) {
	defer clear(value)
	if b == nil || b.manager == nil {
		return receipt, errors.New("secret broker is not configured")
	}
	if err := request.validate(); err != nil {
		return receipt, err
	}
	if len(value) == 0 || len(value) > 1024*1024 {
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
		return receipt, errors.New("strict SSH connection for secret provisioning failed")
	}
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		return receipt, errors.New("open SFTP session for secret provisioning failed")
	}
	defer sftpClient.Close()

	target, err := request.TargetPath()
	if err != nil {
		return receipt, err
	}
	root := path.Dir(target)
	if err := ensurePrivateDirectoryTree(sftpClient, root); err != nil {
		return receipt, err
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		clear(random)
		return receipt, errors.New("generate secret staging name failed")
	}
	suffix := hex.EncodeToString(random)
	clear(random)
	temp := path.Join(root, ".secret-"+suffix)
	file, err := sftpClient.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
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
		return receipt, errors.New("restrict secret staging file permissions failed")
	}
	written, err := file.Write(value)
	expected := len(value)
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
	if _, err := sftpClient.Lstat(target); err == nil {
		_ = sftpClient.Remove(temp)
		return receipt, errors.New("secret version already exists")
	} else if !os.IsNotExist(err) {
		_ = sftpClient.Remove(temp)
		return receipt, errors.New("inspect existing secret version failed")
	}
	if err := sftpClient.Rename(temp, target); err != nil {
		_ = sftpClient.Remove(temp)
		return receipt, errors.New("activate secret file failed")
	}
	info, err := sftpClient.Lstat(target)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return receipt, errors.New("verify secret target failed")
	}
	return ProvisionReceipt{
		TargetPath: target,
		OwnerMode:  "0600",
		Version:    request.Version,
		Digest:     "sha256:" + hex.EncodeToString(pathDigest([]byte(target))),
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
	info, err := sftpClient.Lstat(receipt.TargetPath)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("secret revoke target is not a regular file")
	}
	if err := sftpClient.Remove(receipt.TargetPath); err != nil {
		return errors.New("remove secret file failed")
	}
	return nil
}

func (r ProvisionRequest) validate() error {
	for _, value := range []string{r.Project, r.Environment, r.Service, r.Name} {
		if !scopeSegmentPattern.MatchString(value) {
			return errors.New("invalid secret provisioning scope")
		}
	}
	if !versionSegmentPattern.MatchString(r.Version) {
		return errors.New("invalid secret version")
	}
	return nil
}

func ensurePrivateDirectoryTree(client *sftp.Client, target string) error {
	current := "/"
	for _, segment := range strings.Split(strings.TrimPrefix(target, "/"), "/") {
		current = path.Join(current, segment)
		info, err := client.Lstat(current)
		if os.IsNotExist(err) {
			if err := client.Mkdir(current); err != nil {
				return errors.New("create secret directory failed")
			}
			if err := client.Chmod(current, 0700); err != nil {
				return errors.New("restrict secret directory permissions failed")
			}
			info, err = client.Lstat(current)
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("secret directory contains an invalid path component")
		}
		if current == "/srv/vps-pilot" || strings.HasPrefix(current, "/srv/vps-pilot/") {
			if info.Mode().Perm()&0077 != 0 {
				return errors.New("secret directory permissions are too broad")
			}
		}
	}
	return nil
}

func safeSecretPath(value string) bool {
	if path.Clean(value) != value {
		return false
	}
	segments := strings.Split(strings.TrimPrefix(value, "/"), "/")
	if len(segments) != 7 || segments[0] != "srv" || segments[1] != "vps-pilot" || segments[2] != "secrets" {
		return false
	}
	for _, segment := range segments[3:6] {
		if !scopeSegmentPattern.MatchString(segment) {
			return false
		}
	}
	separator := strings.IndexByte(segments[6], '.')
	if separator <= 0 || separator == len(segments[6])-1 {
		return false
	}
	return scopeSegmentPattern.MatchString(segments[6][:separator]) &&
		versionSegmentPattern.MatchString(segments[6][separator+1:])
}

func pathDigest(value []byte) []byte {
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
