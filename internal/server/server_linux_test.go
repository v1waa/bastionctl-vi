//go:build linux

package server

import (
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"bastionctl/internal/config"
	"bastionctl/internal/report"
)

func TestSnapshotWriteRestore(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "managed.conf")
	if err := os.WriteFile(path, []byte("before\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(directory, "backup")
	snapshot, err := snapshotFile(path, backup, "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := snapshot.Write([]byte("after\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if content, _ := os.ReadFile(path); string(content) != "after\n" {
		t.Fatalf("write failed: %q", content)
	}
	if err := snapshot.Restore(); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil || string(content) != "before\n" {
		t.Fatalf("restore failed: %q %v", content, err)
	}
}

func TestAuditOnlyControlPreservesBlockingFindingDuringApply(t *testing.T) {
	item := functionalControl{
		name: "read-only",
		audit: func(*serverContext) []report.Result {
			return []report.Result{{Control: "read-only", Status: report.Fail, Severity: "critical", Message: "finding"}}
		},
	}
	result := item.Apply(&serverContext{})
	if result.Status != report.Fail {
		t.Fatalf("apply must preserve audit failure, got %+v", result)
	}
}

func TestPreflightManagedPathRejectsSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	link := filepath.Join(directory, "link")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := preflightManagedPath(link); err == nil {
		t.Fatal("symlink should be rejected")
	}
}

func TestFirewallCommandsKeepSafeOrder(t *testing.T) {
	cfg := config.Defaults()
	cfg.Server.SSHAllowedCIDRs = []string{"203.0.113.5/32"}
	ctx := &serverContext{config: cfg, sshPorts: []int{2222}}
	commands := firewallCommands(ctx)
	if got := commands[0]; !reflect.DeepEqual(got, []string{"allow", "proto", "tcp", "from", "203.0.113.5/32", "to", "any", "port", "2222", "comment", "bastionctl-ssh"}) {
		t.Fatalf("first command does not protect SSH: %v", got)
	}
	if got := commands[len(commands)-1]; !reflect.DeepEqual(got, []string{"--force", "enable"}) {
		t.Fatalf("enable must be last: %v", got)
	}
}

func TestIPAllowed(t *testing.T) {
	if !ipAllowed(net.ParseIP("203.0.113.7"), []string{"203.0.113.0/24"}) {
		t.Fatal("IP should be allowed")
	}
	if ipAllowed(net.ParseIP("198.51.100.7"), []string{"203.0.113.0/24"}) {
		t.Fatal("IP should not be allowed")
	}
}

func TestTrailingPort(t *testing.T) {
	for input, expected := range map[string]int{"0.0.0.0:22": 22, "[::]:443": 443, "*:5353": 5353} {
		port, ok := trailingPort(input)
		if !ok || port != expected {
			t.Fatalf("%s: %d %v", input, port, ok)
		}
	}
}
