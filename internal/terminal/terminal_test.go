package terminal

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestPinnedHostKeyCallback(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "known_hosts")
	line := "[example.com]:2222 " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))) + "\n"
	if err := atomicWriteKnownHost(path, []byte(line)); err != nil {
		t.Fatal(err)
	}
	callback, err := PinnedHostKeyCallback(path)
	if err != nil {
		t.Fatal(err)
	}
	remote, _ := net.ResolveTCPAddr("tcp", "192.0.2.10:2222")
	if err := callback("example.com:2222", remote, signer.PublicKey()); err != nil {
		t.Fatal(err)
	}
	_, otherPrivate, _ := ed25519.GenerateKey(rand.Reader)
	other, _ := ssh.NewSignerFromKey(otherPrivate)
	if err := callback("example.com:2222", remote, other.PublicKey()); err == nil {
		t.Fatal("changed host key accepted")
	}
}

func TestAuthenticationMethodsAcceptOpenSSHKey(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(privateKey, "test")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	methods, err := authenticationMethods(path, Credentials{})
	if err != nil || len(methods) != 1 {
		t.Fatalf("methods=%d err=%v", len(methods), err)
	}
	methods, err = authenticationMethods("", Credentials{Password: "temporary"})
	if err != nil || len(methods) != 2 {
		t.Fatalf("password methods=%d err=%v", len(methods), err)
	}
}

func TestSplitTargetAndTerminalSize(t *testing.T) {
	user, host, err := splitTarget("admin@[2001:db8::1]")
	if err != nil || user != "admin" || host != "2001:db8::1" {
		t.Fatalf("user=%q host=%q err=%v", user, host, err)
	}
	for _, invalid := range []string{"host", "root@-bad", "root@host/command", "root@@host"} {
		if _, _, err := splitTarget(invalid); err == nil {
			t.Fatalf("invalid target accepted: %q", invalid)
		}
	}
	columns, rows := safeTerminalSize(1, 1000)
	if columns != 80 || rows != 300 {
		t.Fatalf("size=%dx%d", columns, rows)
	}
}

func TestSecureClientConfigUsesSupportedAlgorithms(t *testing.T) {
	config := secureClientConfig("admin", nil, ssh.InsecureIgnoreHostKey(), 5*time.Second)
	wanted := ssh.SupportedAlgorithms()
	if strings.Join(config.HostKeyAlgorithms, ",") != strings.Join(wanted.HostKeys, ",") ||
		strings.Join(config.KeyExchanges, ",") != strings.Join(wanted.KeyExchanges, ",") {
		t.Fatal("client config does not use supported algorithm set")
	}
	if _, _, err := ProbeHostKey(context.Background(), "admin@127.0.0.1", 1, time.Millisecond); err == nil {
		t.Fatal("unreachable SSH probe unexpectedly succeeded")
	}
}

func TestRemoteUploadPathIsBounded(t *testing.T) {
	valid := "/tmp/bastionctl-bin-0123456789abcdef01234567"
	if !remoteUploadPattern.MatchString(valid) {
		t.Fatalf("expected valid path: %s", valid)
	}
	for _, value := range []string{"/etc/passwd", "/tmp/bastionctl-bin-../../etc", "/tmp/bastionctl-bin-short", "/tmp/bastionctl-other-0123456789abcdef01234567"} {
		if remoteUploadPattern.MatchString(value) {
			t.Fatalf("unsafe path accepted: %s", value)
		}
	}
}

func TestUploadBytesRejectsEmptyAndUnsafePayloads(t *testing.T) {
	if err := UploadBytes(context.Background(), Connection{}, Credentials{}, nil, "/tmp/bastionctl-bin-0123456789abcdef01234567", 1024); err == nil {
		t.Fatal("empty embedded payload was accepted")
	}
	if err := UploadBytes(context.Background(), Connection{}, Credentials{}, []byte("payload"), "/etc/bastionctl", 1024); err == nil {
		t.Fatal("unsafe embedded payload path was accepted")
	}
}
