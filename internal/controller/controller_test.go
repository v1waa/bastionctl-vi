package controller

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"bastionctl/internal/report"
)

func TestAddServerCreatesRoundTripConfig(t *testing.T) {
	control, err := New("test", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	item, err := control.AddServer(AddOptions{
		ID: "web-01", Name: "Web 01", Target: "ops@example.com", Profile: "web",
		SSHAllowedCIDRs: []string{"203.0.113.7/32"}, AdditionalTCPPorts: []int{8443},
		BackupMarkers: []string{"/var/lib/backup/success"}, BackupRequired: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if item.Port != 22 || item.Profile != "web" {
		t.Fatalf("unexpected server: %+v", item)
	}
	cfg, err := control.Config(item.ID)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.AdminUser != "ops" || !cfg.Server.BackupRequired {
		t.Fatalf("unexpected config: %+v", cfg.Server)
	}
	if !reflect.DeepEqual(cfg.Server.AllowedTCPPorts, []int{80, 443, 8443}) {
		t.Fatalf("unexpected ports: %v", cfg.Server.AllowedTCPPorts)
	}
	updated, err := control.UpdateServer(UpdateOptions{
		ID: item.ID, Name: "Renamed", Target: "admin@example.net", Port: 2222,
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Target != "admin@example.net" || updated.Port != 2222 {
		t.Fatalf("connection was not updated: %+v", updated)
	}
	cfg, err = control.Config(item.ID)
	if err != nil || cfg.Server.AdminUser != "admin" {
		t.Fatalf("admin user was not synchronized: %+v err=%v", cfg.Server, err)
	}
	if _, err := control.AddServer(AddOptions{ID: "web-01", Target: "ops@example.com"}); err == nil {
		t.Fatal("duplicate ID was accepted")
	}
	if err := control.RemoveServer(item.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(item.ConfigPath); err != nil {
		t.Fatalf("remove should preserve local recovery data: %v", err)
	}
}

func TestPasswordBootstrapCreatesDedicatedKeyAndNonRootTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test helper uses a POSIX script")
	}
	directory := t.TempDir()
	keygen := filepath.Join(directory, "ssh-keygen")
	script := `#!/bin/sh
target=''
while [ "$#" -gt 0 ]; do
  if [ "$1" = '-f' ]; then shift; target=$1; fi
  shift
done
printf '%s\n' 'private' > "$target"
printf '%s\n' "$BASTIONCTL_TEST_PUBLIC_KEY" > "$target.pub"
`
	if err := os.WriteFile(keygen, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory)
	t.Setenv("BASTIONCTL_TEST_PUBLIC_KEY", controllerTestPublicKey())
	control, err := New("test", filepath.Join(directory, "state"))
	if err != nil {
		t.Fatal(err)
	}
	item, err := control.AddServer(AddOptions{
		ID: "fresh", Target: "root@192.0.2.25", Profile: "minimal",
		PasswordBootstrap: true, BootstrapAdminUser: "guard",
	})
	if err != nil {
		t.Fatal(err)
	}
	if item.Target != "guard@192.0.2.25" || item.BootstrapTarget != "root@192.0.2.25" || !item.BootstrapPending || !item.InteractiveSudo {
		t.Fatalf("unexpected bootstrap state: %+v", item)
	}
	if !strings.HasSuffix(item.Identity, filepath.Join("fresh", "id_ed25519")) {
		t.Fatalf("unexpected identity path: %s", item.Identity)
	}
	cfg, err := control.Config(item.ID)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.AdminUser != "guard" || cfg.Admin.StrictHostKeyChecking {
		t.Fatalf("unexpected bootstrap config: %+v", cfg)
	}
	if _, err := control.AddServer(AddOptions{ID: "unsafe", Target: "root@192.0.2.26"}); err == nil {
		t.Fatal("persistent root target was accepted without bootstrap")
	}
}

func TestCaptureSnapshotCreatesBaselineThenDiff(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test helper uses a POSIX script")
	}
	control, err := New("test", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := control.AddServer(AddOptions{ID: "alpha", Target: "ops@example.com", AcceptNewHostKey: true}); err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	ssh := filepath.Join(directory, "ssh")
	writeSnapshotSSH := func(listener string) {
		t.Helper()
		script := "#!/bin/sh\nprintf '%s\\n' '" + listener + "'\n"
		if err := os.WriteFile(ssh, []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	base := `{"schema":"bastionctl.snapshot.v1","tool_version":"test","captured_at":"2026-08-20T10:00:00Z","host":{"hostname":"alpha","distribution":"Ubuntu","version":"24.04","kernel":"1","architecture":"amd64"},"packages":[],"services":[],"accounts":[],"listeners":[],"files":[]}`
	writeSnapshotSSH(base)
	t.Setenv("PATH", directory)
	first, err := control.CaptureSnapshot(context.Background(), "alpha", false)
	if err != nil || !first.BaselineCreated {
		t.Fatalf("first=%+v err=%v", first, err)
	}
	cfg, err := control.Config("alpha")
	if err != nil || !cfg.Admin.StrictHostKeyChecking {
		t.Fatalf("host key policy was not promoted: %+v err=%v", cfg.Admin, err)
	}
	changed := `{"schema":"bastionctl.snapshot.v1","tool_version":"test","captured_at":"2026-08-20T11:00:00Z","host":{"hostname":"alpha","distribution":"Ubuntu","version":"24.04","kernel":"1","architecture":"amd64"},"packages":[],"services":[],"accounts":[],"listeners":[{"protocol":"tcp","address":"0.0.0.0","port":8080}],"files":[]}`
	writeSnapshotSSH(changed)
	second, err := control.CaptureSnapshot(context.Background(), "alpha", false)
	if err != nil || second.Diff == nil || len(second.Diff.Changes) != 1 {
		t.Fatalf("second=%+v err=%v", second, err)
	}
}

func TestFindNewFailures(t *testing.T) {
	// Kept in controller package so failure comparison remains deterministic as reports evolve.
	previous := sampleReport("ssh")
	current := sampleReport("ssh", "firewall", "backup")
	got := findNewFailures(previous, current)
	want := []string{"backup", "firewall"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func sampleReport(controls ...string) *report.Report {
	value := report.New("test", "admin", "audit", "example")
	for _, control := range controls {
		value.Add(report.Result{Control: control, Status: report.Fail, Message: "finding"})
	}
	return value
}

func controllerTestPublicKey() string {
	var blob bytes.Buffer
	write := func(value []byte) {
		_ = binary.Write(&blob, binary.BigEndian, uint32(len(value)))
		_, _ = blob.Write(value)
	}
	write([]byte("ssh-ed25519"))
	write(bytes.Repeat([]byte{0x24}, 32))
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob.Bytes()) + " test"
}
