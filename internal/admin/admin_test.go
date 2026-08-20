package admin

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"bastionctl/internal/config"
	"bastionctl/internal/report"
)

func TestValidateTarget(t *testing.T) {
	valid := []string{"admin@example.com", "ops@192.0.2.10", "ops@[2001:db8::10]", "first.last@host-1.example"}
	for _, target := range valid {
		if err := ValidateTarget(target); err != nil {
			t.Errorf("%s should be valid: %v", target, err)
		}
	}
	invalid := []string{"example.com", "-oProxyCommand=x@y", "root@-host", "root@host name", "root@@host", "root@host/command"}
	for _, target := range invalid {
		if err := ValidateTarget(target); err == nil {
			t.Errorf("%s should be rejected", target)
		}
	}
}

func TestELFArchitecture(t *testing.T) {
	for machine, expected := range map[uint16]string{62: "amd64", 183: "arm64"} {
		header := make([]byte, 20)
		copy(header, []byte{0x7f, 'E', 'L', 'F'})
		header[4] = 2
		header[5] = 1
		binary.LittleEndian.PutUint16(header[18:20], machine)
		path := filepath.Join(t.TempDir(), expected)
		if err := os.WriteFile(path, header, 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := ELFArchitecture(path)
		if err != nil || got != expected {
			t.Fatalf("machine %d: got=%q err=%v", machine, got, err)
		}
	}
}

func TestLastNonEmptyLine(t *testing.T) {
	if got := lastNonEmptyLine("file: OK\n1.0.0\n\n"); got != "1.0.0" {
		t.Fatalf("got %q", got)
	}
}

func TestShellQuote(t *testing.T) {
	if got, want := shellQuote("a'b"), `'a'"'"'b'`; got != want {
		t.Fatalf("shellQuote = %q, want %q", got, want)
	}
}

func TestRunAcceptsFindingExitCodeWithValidReport(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test helper uses a POSIX script")
	}
	directory := t.TempDir()
	ssh := filepath.Join(directory, "ssh")
	script := `#!/bin/sh
printf '%s\n' '{"schema":"bastionctl.report.v1","tool_version":"test","mode":"server","action":"audit","started_at":"2026-01-01T00:00:00Z","finished_at":"2026-01-01T00:00:01Z","summary":{"pass":0,"fail":1,"warn":0,"info":0,"planned":0,"changed":0,"skipped":0},"results":[{"control":"ssh","status":"fail","message":"finding"}]}'
exit 2
`
	if err := os.WriteFile(ssh, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory)
	cfg := config.Defaults().Admin
	r := Run(context.Background(), cfg, "test", Options{Action: "audit", Target: "ops@example.com", Port: 22})
	if len(r.Results) != 1 || r.Results[0].Control != "ssh" || r.Results[0].Status != report.Fail {
		t.Fatalf("remote findings were not preserved: %+v", r)
	}
}

func TestInstallWithVerifiedFakeTransport(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test helper uses POSIX scripts")
	}
	directory := t.TempDir()
	ssh := filepath.Join(directory, "ssh")
	scp := filepath.Join(directory, "scp")
	sshScript := `#!/bin/sh
case "$*" in
  *"'uname' '-m'"*) printf '%s\n' 'x86_64' ;;
  *) printf '%s\n' '/tmp/bastionctl: OK' '1.0.0' ;;
esac
`
	if err := os.WriteFile(ssh, []byte(sshScript), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(scp, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	header := make([]byte, 20)
	copy(header, []byte{0x7f, 'E', 'L', 'F'})
	header[4] = 2
	header[5] = 1
	binary.LittleEndian.PutUint16(header[18:20], 62)
	binaryPath := filepath.Join(directory, "bastionctl-linux-amd64")
	if err := os.WriteFile(binaryPath, header, 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, "config.toml")
	configData, err := config.Render(config.Defaults())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, configData, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory)
	r := Install(context.Background(), config.Defaults().Admin, "1.0.0", InstallOptions{
		Connection: Options{Target: "ops@example.com", Port: 22}, BinaryPath: binaryPath,
		ConfigPath: configPath, InstallSudo: true, ExpectedArch: "amd64",
	})
	if r.HasFailures() {
		t.Fatalf("install failed: %+v", r.Results)
	}
	if len(r.Results) != 4 || r.Results[2].Details["version"] != "1.0.0" {
		t.Fatalf("unexpected install report: %+v", r.Results)
	}
}

func TestGenerateIdentityAndReadPublicKey(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test helper uses a POSIX script")
	}
	directory := t.TempDir()
	keygen := filepath.Join(directory, "ssh-keygen")
	script := `#!/bin/sh
target=''
while [ "$#" -gt 0 ]; do
  if [ "$1" = '-f' ]; then
    shift
    target=$1
  fi
  shift
done
[ -n "$target" ] || exit 64
printf '%s\n' 'test-private-key' > "$target"
printf '%s\n' "$BASTIONCTL_TEST_PUBLIC_KEY" > "$target.pub"
`
	if err := os.WriteFile(keygen, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory)
	t.Setenv("BASTIONCTL_TEST_PUBLIC_KEY", testPublicKey())
	path := filepath.Join(directory, "id_ed25519")
	if err := GenerateIdentity(context.Background(), path, "bastionctl:test"); err != nil {
		t.Fatal(err)
	}
	if key, err := ReadPublicKey(path + ".pub"); err != nil || !strings.HasPrefix(key, "ssh-ed25519 ") {
		t.Fatalf("key=%q err=%v", key, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode=%v", info.Mode().Perm())
	}
}

func TestBootstrapUsesPasswordOnlyInsideOpenSSH(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test helper uses a POSIX script")
	}
	directory := t.TempDir()
	ssh := filepath.Join(directory, "ssh")
	logPath := filepath.Join(directory, "ssh.log")
	script := `#!/bin/sh
printf '%s\n' "$*" >> "$BASTIONCTL_TEST_LOG"
case "$*" in
  *'BatchMode=yes'*) printf '%s\n' 'bastionctl-key-ok' ;;
esac
`
	if err := os.WriteFile(ssh, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(directory, "id_ed25519")
	if err := os.WriteFile(privatePath, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(privatePath+".pub", []byte(testPublicKey()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	terminal, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer terminal.Close()
	t.Setenv("PATH", directory)
	t.Setenv("BASTIONCTL_TEST_LOG", logPath)
	cfg := config.Defaults().Admin
	cfg.StrictHostKeyChecking = false
	var output bytes.Buffer
	err = BootstrapKey(context.Background(), cfg, BootstrapOptions{
		Login:         Options{Target: "root@192.0.2.10", Port: 22, Identity: privatePath},
		ManagedTarget: "guard@192.0.2.10", PublicKeyPath: privatePath + ".pub",
		Input: terminal, Output: &output,
	})
	if err != nil {
		t.Fatal(err)
	}
	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	logText := string(logData)
	for _, expected := range []string{"BatchMode=no", "PubkeyAuthentication=no", "PasswordAuthentication=yes", "BatchMode=yes", "PasswordAuthentication=no", "StrictHostKeyChecking=ask", "StrictHostKeyChecking=yes"} {
		if !strings.Contains(logText, expected) {
			t.Fatalf("missing %q in ssh arguments: %s", expected, logText)
		}
	}
	if strings.Contains(strings.ToLower(logText), "--password") || strings.Contains(strings.ToLower(logText), "pass=") {
		t.Fatalf("password-like argument leaked to ssh command: %s", logText)
	}
}

func TestBootstrapCommandSeparatesRootAndManagedUser(t *testing.T) {
	command := bootstrapAuthorizedKeyCommand("root", "guard", testPublicKey())
	for _, expected := range []string{"apt-get install -y sudo", "useradd", "usermod -aG sudo", "passwd -S", "authorized_keys"} {
		if !strings.Contains(command, expected) {
			t.Fatalf("missing %q: %s", expected, command)
		}
	}
	self := bootstrapAuthorizedKeyCommand("ops", "ops", testPublicKey())
	if strings.Contains(self, "useradd") || !strings.Contains(self, "authorized_keys") {
		t.Fatalf("unexpected self-bootstrap command: %s", self)
	}
}

func testPublicKey() string {
	var blob bytes.Buffer
	write := func(value []byte) {
		_ = binary.Write(&blob, binary.BigEndian, uint32(len(value)))
		_, _ = blob.Write(value)
	}
	write([]byte("ssh-ed25519"))
	write(bytes.Repeat([]byte{0x42}, 32))
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob.Bytes()) + " bastionctl-test"
}
