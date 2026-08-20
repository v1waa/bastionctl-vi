package inventory

import (
	"testing"
	"time"
)

func TestCompareDetectsSecurityRelevantDrift(t *testing.T) {
	baseline := testSnapshot()
	current := testSnapshot()
	current.CapturedAt = current.CapturedAt.Add(time.Hour)
	current.Services[0].Active = "inactive"
	current.Accounts = append(current.Accounts, Account{Name: "mystery", UID: 0, GID: 0, Shell: "/bin/bash"})
	current.Listeners = append(current.Listeners, Listener{Protocol: "tcp", Address: "0.0.0.0", Port: 8080})
	current.Files[0].SHA256 = "changed"
	diff, err := Compare(baseline, current)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.Changes) != 4 {
		t.Fatalf("unexpected changes: %+v", diff.Changes)
	}
	if diff.Changes[0].Category != "account" || diff.Changes[len(diff.Changes)-1].Category != "service" {
		t.Fatalf("changes not sorted: %+v", diff.Changes)
	}
}

func testSnapshot() Snapshot {
	return Snapshot{
		Schema: Schema, ToolVersion: "test", CapturedAt: time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC),
		Host:      Host{Hostname: "alpha", Architecture: "amd64", Kernel: "1"},
		Packages:  []Package{{Name: "openssh-server", Version: "1"}},
		Services:  []Service{{Name: "ssh.service", Active: "active", Enabled: "enabled"}},
		Accounts:  []Account{{Name: "root", UID: 0, GID: 0, Shell: "/bin/bash"}},
		Listeners: []Listener{{Protocol: "tcp", Address: "0.0.0.0", Port: 22}},
		Files:     []FileDigest{{Path: "/etc/ssh/sshd_config", Exists: true, SHA256: "base", Mode: "0600"}},
	}
}
