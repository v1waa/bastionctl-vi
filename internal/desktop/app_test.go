package desktop

import (
	"strings"
	"testing"
)

func TestDesktopServerLifecycleAndSecuritySettings(t *testing.T) {
	app, err := New("test", t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Close)

	created, err := app.AddServer(AddServerRequest{
		ID: "prod-1", Name: "Production", Target: "ops@192.0.2.20", Port: 22, Profile: "minimal",
		SSHAllowedCIDRs: []string{"198.51.100.7/32"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.HostKeyTrusted || created.BootstrapPending {
		t.Fatalf("unexpected new server state: %+v", created)
	}

	settings, err := app.SecuritySettings(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	settings.AllowedTCPPorts = "443, 80, 443"
	settings.AllowedUDPPorts = "51820"
	settings.BackupMarkers = "/var/backups/app.ok\n/var/backups/db.ok"
	if err := app.SaveSecuritySettings(created.ID, settings); err != nil {
		t.Fatal(err)
	}
	saved, err := app.SecuritySettings(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if saved.AllowedTCPPorts != "80, 443" || saved.AllowedUDPPorts != "51820" {
		t.Fatalf("ports were not normalised: %+v", saved)
	}

	if err := app.RemoveServer(created.ID, "prod-1"); err == nil {
		t.Fatal("remove accepted without exact confirmation")
	}
	if err := app.RemoveServer(created.ID, "REMOVE prod-1"); err != nil {
		t.Fatal(err)
	}
}

func TestConfigureXHTTPPreservesPanelPath(t *testing.T) {
	app, err := New("test", t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Close)
	if _, err := app.AddServer(AddServerRequest{
		ID: "xhttp", Name: "XHTTP", Target: "ops@192.0.2.22", Port: 22, Profile: "web",
	}); err != nil {
		t.Fatal(err)
	}
	first, err := app.ConfigureXHTTP(XHTTPRequest{
		ServerID: "xhttp", Domain: "vpn.example.com", Email: "admin@example.com",
		ServerIP: "8.8.8.8", PanelPort: 18080,
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := app.ConfigureXHTTP(XHTTPRequest{
		ServerID: "xhttp", Domain: "new.example.com", Email: "security@example.com",
		ServerIP: "8.8.4.4", PanelPort: 19090,
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.Config.WebBasePath == "" || second.Config.WebBasePath != first.Config.WebBasePath {
		t.Fatalf("panel path changed during update: %q -> %q", first.Config.WebBasePath, second.Config.WebBasePath)
	}
	if second.Config.PanelPort != 19090 || second.Config.Domain != "new.example.com" {
		t.Fatalf("requested XHTTP update was not saved: %+v", second.Config)
	}
}

func TestDesktopRejectsUntrustedTerminalAndUnsafeConfirmation(t *testing.T) {
	app, err := New("test", t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Close)
	_, err = app.AddServer(AddServerRequest{ID: "edge", Name: "Edge", Target: "ops@192.0.2.21", Port: 22, Profile: "minimal"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.StartTerminal(TerminalRequest{ServerID: "edge"}); err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("unexpected terminal error: %v", err)
	}
	if _, err := app.RunSecurityAction(SecurityActionRequest{ServerID: "edge", Action: "apply", Confirmation: "yes"}); err == nil {
		t.Fatal("apply accepted without exact confirmation")
	}
	if _, err := parsePorts("22, nope"); err == nil {
		t.Fatal("invalid port accepted")
	}
}
