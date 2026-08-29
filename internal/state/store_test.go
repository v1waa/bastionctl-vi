package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"bastionctl/internal/inventory"
)

func TestRegistryAndManagedConfig(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	configPath, err := store.SaveServerConfig("alpha", []byte("[server]\n"))
	if err != nil {
		t.Fatal(err)
	}
	item := ManagedServer{ID: "alpha", Name: "Alpha", Target: "ops@example.com", Port: 22, Profile: "minimal", ConfigPath: configPath}
	if err := store.AddServer(item); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Server("alpha")
	if err != nil || loaded.Target != item.Target {
		t.Fatalf("loaded=%+v err=%v", loaded, err)
	}
	bad := item
	bad.ID = "beta"
	bad.ConfigPath = filepath.Join(store.Root(), "registry.json")
	if err := store.AddServer(bad); err == nil || !strings.Contains(err.Error(), "config_path") {
		t.Fatalf("unsafe config path accepted: %v", err)
	}
}

func TestSignedSnapshotRejectsReplacementKey(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	snapshot := inventory.Snapshot{
		Schema: inventory.Schema, ToolVersion: "test", CapturedAt: time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC),
		Host:     inventory.Host{Hostname: "alpha", Architecture: "amd64"},
		Packages: []inventory.Package{}, Services: []inventory.Service{}, Accounts: []inventory.Account{},
		Listeners: []inventory.Listener{}, Files: []inventory.FileDigest{},
	}
	if err := store.SaveSnapshot("alpha", snapshot, true); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.LoadSnapshot("alpha", "baseline")
	if err != nil || loaded.Host.Hostname != "alpha" {
		t.Fatalf("loaded=%+v err=%v", loaded, err)
	}

	payload, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	replacement := SignedSnapshot{
		Schema: "bastionctl.signed-snapshot.v1", Snapshot: snapshot,
		PublicKey: base64.StdEncoding.EncodeToString(publicKey),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload)),
	}
	data, err := json.Marshal(replacement)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(store.Root(), "snapshots", "alpha", "baseline.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadSnapshot("alpha", "baseline"); err == nil || !strings.Contains(err.Error(), "неизвестным") {
		t.Fatalf("replacement key was accepted: %v", err)
	}
}

func TestValidateID(t *testing.T) {
	for _, value := range []string{"alpha", "server-01", "db_prod"} {
		if err := ValidateID(value); err != nil {
			t.Errorf("%q: %v", value, err)
		}
	}
	for _, value := range []string{"", "UPPER", "../bad", "a/b", strings.Repeat("a", 33)} {
		if err := ValidateID(value); err == nil {
			t.Errorf("%q should be rejected", value)
		}
	}
}

func TestWorkloadConfigUsesConfinedServerPath(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path, err := store.SaveWorkloadConfig("alpha", "xhttp", []byte("{}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(path, filepath.Join("servers", "alpha", "workloads", "xhttp.json")) {
		t.Fatalf("unexpected path: %s", path)
	}
	data, err := store.LoadWorkloadConfig("alpha", "xhttp")
	if err != nil || string(data) != "{}\n" {
		t.Fatalf("data=%q err=%v", data, err)
	}
	for _, unsafe := range []string{"../x", "XHTTP", "a/b"} {
		if _, err := store.SaveWorkloadConfig("alpha", unsafe, []byte("x")); err == nil {
			t.Fatalf("unsafe workload name accepted: %q", unsafe)
		}
	}
}

func TestRegistryV1MigratesToV2OnWrite(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	configPath, err := store.SaveServerConfig("legacy", []byte("[server]\n"))
	if err != nil {
		t.Fatal(err)
	}
	legacy := Registry{
		Schema:  legacyRegistrySchema,
		Servers: []ManagedServer{{ID: "legacy", Name: "Legacy", Target: "ops@example.com", Port: 22, Profile: "minimal", ConfigPath: configPath}},
	}
	data, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store.Root(), "registry.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.LoadRegistry()
	if err != nil || loaded.Schema != registrySchema {
		t.Fatalf("loaded=%+v err=%v", loaded, err)
	}
	item := loaded.Servers[0]
	item.Name = "Migrated"
	if err := store.UpdateServer(item); err != nil {
		t.Fatal(err)
	}
	written, err := os.ReadFile(filepath.Join(store.Root(), "registry.json"))
	if err != nil || !strings.Contains(string(written), registrySchema) {
		t.Fatalf("registry was not migrated: %q err=%v", written, err)
	}
}
