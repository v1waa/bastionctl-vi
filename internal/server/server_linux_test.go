//go:build linux

package server

import (
	"context"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"strings"
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

func TestTaggedUFWRulesAreDeletedInDescendingOrder(t *testing.T) {
	output := `Status: active

[ 1] 22/tcp ALLOW IN Anywhere # bastionctl-ssh
[ 2] 443/tcp ALLOW IN Anywhere # customer-rule
[ 3] 8080/tcp ALLOW IN Anywhere # keep-bastionctl-service-copy
[12] 51820/udp ALLOW IN Anywhere # bastionctl-service
[ 4] 22/tcp (v6) ALLOW IN Anywhere (v6) # bastionctl-ssh`
	want := []int{12, 4, 1}
	if got := taggedUFWRules(output); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestTaggedUFWRulesCanBeFilteredBySafetyKind(t *testing.T) {
	output := "[ 1] 22/tcp ALLOW IN Anywhere # bastionctl-ssh\n[ 7] 443/tcp ALLOW IN Anywhere # bastionctl-service\n"
	if got := taggedUFWRulesByKind(output, "ssh"); !reflect.DeepEqual(got, []int{1}) {
		t.Fatalf("ssh rules: %v", got)
	}
	if got := taggedUFWRulesByKind(output, "service"); !reflect.DeepEqual(got, []int{7}) {
		t.Fatalf("service rules: %v", got)
	}
}

func TestResettableUFWRulesPreserveSSHUnderDefaultDeny(t *testing.T) {
	directory := t.TempDir()
	ufw := filepath.Join(directory, "ufw")
	if err := os.WriteFile(ufw, []byte("#!/bin/sh\nprintf '%s\\n' 'Status: active' 'Default: deny (incoming), allow (outgoing)'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
	numbered := "[ 1] 22/tcp ALLOW IN Anywhere # bastionctl-ssh\n[ 7] 443/tcp ALLOW IN Anywhere # bastionctl-service\n"
	deletable, preserved, warning := resettableUFWRules(context.Background(), numbered)
	if !reflect.DeepEqual(deletable, []int{7}) || !reflect.DeepEqual(preserved, []int{1}) || warning == "" {
		t.Fatalf("deletable=%v preserved=%v warning=%q", deletable, preserved, warning)
	}
}

func TestResettableUFWRulesPreserveSSHWhenPolicyIsUnclear(t *testing.T) {
	directory := t.TempDir()
	ufw := filepath.Join(directory, "ufw")
	if err := os.WriteFile(ufw, []byte("#!/bin/sh\nprintf '%s\\n' 'Status output is localized'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
	numbered := "[ 2] 22/tcp ALLOW IN Anywhere # bastionctl-ssh\n[ 8] 443/tcp ALLOW IN Anywhere # bastionctl-service\n"
	deletable, preserved, warning := resettableUFWRules(context.Background(), numbered)
	if !reflect.DeepEqual(deletable, []int{8}) || !reflect.DeepEqual(preserved, []int{2}) || warning == "" {
		t.Fatalf("deletable=%v preserved=%v warning=%q", deletable, preserved, warning)
	}
}

func TestInspectResetFileRequiresOwnershipMarker(t *testing.T) {
	directory := t.TempDir()
	managed := filepath.Join(directory, "managed.conf")
	foreign := filepath.Join(directory, "foreign.conf")
	lookalike := filepath.Join(directory, "lookalike.conf")
	if err := os.WriteFile(managed, []byte("# Managed by bastionctl.\nvalue=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(foreign, []byte("value=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lookalike, []byte("# Not Managed by bastionctl.\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if owned, exists, err := inspectResetFile(managed); err != nil || !owned || !exists {
		t.Fatalf("managed: owned=%v exists=%v err=%v", owned, exists, err)
	}
	if owned, exists, err := inspectResetFile(foreign); err != nil || owned || !exists {
		t.Fatalf("foreign: owned=%v exists=%v err=%v", owned, exists, err)
	}
	if owned, exists, err := inspectResetFile(lookalike); err != nil || owned || !exists {
		t.Fatalf("lookalike: owned=%v exists=%v err=%v", owned, exists, err)
	}
}

func TestInstallAuthorizedKeyAppendsAndIsIdempotent(t *testing.T) {
	home := t.TempDir()
	account := &user.User{Username: "testuser", HomeDir: home}
	uid, gid := os.Getuid(), os.Getgid()
	path, added, err := installAuthorizedKey(account, uid, gid, userTestPublicKey())
	if err != nil || !added {
		t.Fatalf("first add path=%q added=%v err=%v", path, added, err)
	}
	sameKeyNewComment := strings.TrimSuffix(userTestPublicKey(), " server-test") + " another-comment"
	pathAgain, addedAgain, err := installAuthorizedKey(account, uid, gid, sameKeyNewComment)
	if err != nil || addedAgain || pathAgain != path {
		t.Fatalf("second add path=%q added=%v err=%v", pathAgain, addedAgain, err)
	}
	content, err := os.ReadFile(path)
	if err != nil || strings.Count(string(content), "ssh-ed25519 ") != 1 {
		t.Fatalf("authorized_keys=%q err=%v", content, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%v", info.Mode().Perm())
	}
}

func TestInstallAuthorizedKeyRejectsSymlinkDirectory(t *testing.T) {
	home := t.TempDir()
	target := t.TempDir()
	if err := os.Symlink(target, filepath.Join(home, ".ssh")); err != nil {
		t.Fatal(err)
	}
	account := &user.User{Username: "testuser", HomeDir: home}
	if _, _, err := installAuthorizedKey(account, os.Getuid(), os.Getgid(), userTestPublicKey()); err == nil {
		t.Fatal("symlink .ssh must be rejected")
	}
}
