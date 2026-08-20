package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestLoadExample(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "config.example.toml"))
	if err != nil {
		t.Fatalf("Load example: %v", err)
	}
	if !cfg.Server.ManageSSH || !cfg.Server.ManageFirewall || !cfg.Admin.StrictHostKeyChecking {
		t.Fatalf("security defaults were not preserved: %+v", cfg)
	}
	if len(cfg.Server.AllowedTCPPorts) != 0 {
		t.Fatalf("unexpected TCP ports: %v", cfg.Server.AllowedTCPPorts)
	}
}

func TestLoadRejectsUnknownAndDuplicateKeys(t *testing.T) {
	for _, source := range []string{
		"[server]\nunknown = true\n",
		"[admin]\nconnect_timeout = 5\nconnect_timeout = 6\n",
	} {
		path := writeConfig(t, source)
		if _, err := Load(path); err == nil {
			t.Fatalf("expected error for %q", source)
		}
	}
}

func TestLoadParsesCommentsAndCanonicalizesPorts(t *testing.T) {
	source := `[server]
admin_user = "operator" # inline comment
allowed_tcp_ports = [443, 80, 443]
ssh_allowed_cidrs = ["203.0.113.7/32", "2001:db8::/48"]

[admin]
connect_timeout = 7
`
	path := writeConfig(t, source)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.Server.AllowedTCPPorts; !reflect.DeepEqual(got, []int{80, 443}) {
		t.Fatalf("ports not sorted/deduplicated: %v", got)
	}
	if cfg.Server.AdminUser != "operator" || cfg.Admin.ConnectTimeout != 7 {
		t.Fatalf("unexpected values: %+v", cfg)
	}
}

func TestValidateRejectsUnsafePolicy(t *testing.T) {
	cfg := Defaults()
	cfg.Server.PasswordAuthentication = true
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "password_authentication") {
		t.Fatalf("expected password policy error, got %v", err)
	}
	cfg = Defaults()
	cfg.Admin.RemoteExecutable = "/usr/local/bin/../bad"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected unsafe path error")
	}
}

func TestRenderRoundTrip(t *testing.T) {
	cfg := Defaults()
	cfg.Server.Profile = "web"
	cfg.Server.AdminUser = "operator"
	cfg.Server.SSHAllowedCIDRs = []string{"203.0.113.7/32"}
	cfg.Server.AllowedTCPPorts = []int{443, 80, 443}
	cfg.Server.BackupMarkers = []string{"/var/lib/backup/ok"}
	cfg.Server.BackupRequired = true
	cfg.Admin.StrictHostKeyChecking = false
	data, err := Render(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "rendered.toml")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Server.Profile != "web" || loaded.Server.AdminUser != "operator" || !loaded.Server.BackupRequired {
		t.Fatalf("round trip lost values: %+v", loaded)
	}
	if !reflect.DeepEqual(loaded.Server.AllowedTCPPorts, []int{80, 443}) {
		t.Fatalf("ports not canonical: %v", loaded.Server.AllowedTCPPorts)
	}
	if loaded.Admin.StrictHostKeyChecking {
		t.Fatal("admin policy was not preserved")
	}
}

func writeConfig(t *testing.T, source string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
