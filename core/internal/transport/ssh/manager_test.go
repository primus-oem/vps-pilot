package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestValidateConfigRejectsMissingKnownHosts(t *testing.T) {
	cfg := Config{
		Alias:          "test",
		Host:           "127.0.0.1",
		User:           "deploy",
		Port:           22,
		KnownHostsFile: filepath.Join(t.TempDir(), "missing"),
	}
	if err := validateConfig(cfg); err == nil {
		t.Fatal("expected missing known_hosts to be rejected")
	}
}

func TestValidateConfigRejectsKnownHostsSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "known-hosts")
	if err := os.WriteFile(target, nil, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "known_hosts")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	cfg := Config{
		Alias:          "test",
		Host:           "127.0.0.1",
		User:           "deploy",
		Port:           22,
		KnownHostsFile: link,
	}
	if err := validateConfig(cfg); err == nil {
		t.Fatal("expected symlink known_hosts to be rejected")
	}
}

func TestAuthMethodsRequireIdentity(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	if _, err := authMethods(nil); err == nil {
		t.Fatal("expected missing SSH identity to be rejected")
	}
}

func TestResolveAliasFromOpenSSHConfig(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	sshDir := filepath.Join(root, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		t.Fatal(err)
	}
	config := "Host staging\n  HostName 192.0.2.20\n  User deploy\n  Port 2222\n  IdentityFile ~/.ssh/id_ed25519\n"
	if err := os.WriteFile(filepath.Join(sshDir, "config"), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := ResolveAlias("staging")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Host != "192.0.2.20" || cfg.User != "deploy" || cfg.Port != 2222 {
		t.Fatalf("unexpected resolved config: %#v", cfg)
	}
}

func TestManagerConnectsToDisposableSSHServer(t *testing.T) {
	_, hostPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	serverConfig := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, _ ssh.PublicKey) (*ssh.Permissions, error) {
		return &ssh.Permissions{}, nil
	}}
	serverConfig.AddHostKey(hostSigner)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for i := 0; i < 2; i++ {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			sshConn, channels, requests, err := ssh.NewServerConn(conn, serverConfig)
			if err != nil {
				_ = conn.Close()
				return
			}
			go ssh.DiscardRequests(requests)
			go func() {
				for channel := range channels {
					_ = channel.Reject(ssh.UnknownChannelType, "unsupported")
				}
			}()
			_ = sshConn.Wait()
		}
	}()

	_, identityPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	identityDER, err := x509.MarshalPKCS8PrivateKey(identityPrivate)
	if err != nil {
		t.Fatal(err)
	}
	identityPath := filepath.Join(root, "id_ed25519")
	identityPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: identityDER})
	if err := os.WriteFile(identityPath, identityPEM, 0600); err != nil {
		t.Fatal(err)
	}

	hostPort := listener.Addr().(*net.TCPAddr)
	knownHostsPath := filepath.Join(root, "known_hosts")
	line := knownhosts.Line([]string{fmt.Sprintf("[%s]:%d", hostPort.IP.String(), hostPort.Port)}, hostSigner.PublicKey())
	if err := os.WriteFile(knownHostsPath, []byte(strings.TrimSpace(line)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	manager := NewManager()
	defer manager.Close()
	cfg := Config{
		Alias: "fixture", Host: "127.0.0.1", User: "deploy", Port: hostPort.Port,
		IdentityFiles: []string{identityPath}, KnownHostsFile: knownHostsPath, Timeout: time.Second,
	}
	client, err := manager.Connect(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if client == nil {
		t.Fatal("expected SSH client")
	}
	reused, err := manager.Connect(t.Context(), cfg)
	if err != nil || reused != client {
		t.Fatalf("expected live connection reuse, client=%p err=%v", reused, err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	reconnected, err := manager.Connect(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if reconnected == client {
		t.Fatal("returned closed SSH connection")
	}
}

func TestManagerRejectsChangedHostKey(t *testing.T) {
	_, hostPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	_, wrongPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongSigner, err := ssh.NewSignerFromKey(wrongPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, _ ssh.PublicKey) (*ssh.Permissions, error) {
		return &ssh.Permissions{}, nil
	}}
	serverConfig.AddHostKey(hostSigner)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		serverConn, _, requests, err := ssh.NewServerConn(conn, serverConfig)
		if err != nil {
			_ = conn.Close()
			return
		}
		go ssh.DiscardRequests(requests)
		_ = serverConn.Wait()
	}()
	_, identityPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	identityDER, err := x509.MarshalPKCS8PrivateKey(identityPrivate)
	if err != nil {
		t.Fatal(err)
	}
	identityPath := filepath.Join(root, "identity")
	if err := os.WriteFile(identityPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: identityDER}), 0600); err != nil {
		t.Fatal(err)
	}
	hostPort := listener.Addr().(*net.TCPAddr)
	knownHostsPath := filepath.Join(root, "known_hosts")
	line := knownhosts.Line([]string{fmt.Sprintf("[%s]:%d", hostPort.IP, hostPort.Port)}, wrongSigner.PublicKey())
	if err := os.WriteFile(knownHostsPath, []byte(line+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	manager := NewManager()
	defer manager.Close()
	_, err = manager.Connect(t.Context(), Config{
		Alias: "changed", Host: "127.0.0.1", User: "deploy", Port: hostPort.Port,
		IdentityFiles: []string{identityPath}, KnownHostsFile: knownHostsPath, Timeout: time.Second,
	})
	if err == nil {
		t.Fatal("expected changed SSH host key to be rejected")
	}
}
