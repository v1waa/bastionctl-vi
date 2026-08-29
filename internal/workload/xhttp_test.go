package workload

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestXHTTPConfigAndGuide(t *testing.T) {
	value, err := NewXHTTPConfig("vpn.example.com", "admin@example.com", "203.0.113.10", 24443)
	if err != nil {
		t.Fatal(err)
	}
	if value.Release != XHTTPRelease || value.WebBasePath == "" {
		t.Fatalf("unexpected config: %+v", value)
	}
	steps := ManualGuide(value, "ops@203.0.113.10", "/keys/server key", 2222, 18080)
	if len(steps) != 3 {
		t.Fatalf("steps=%d", len(steps))
	}
	joined := ""
	for _, step := range steps {
		joined += step.Title + strings.Join(step.Details, "\n")
	}
	for _, expected := range []string{"127.0.0.1:18080", "127.0.0.1:24443", "fullchain.pem", "Get New ECH Cert", `-i '/keys/server key'`} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("guide lacks %q:\n%s", expected, joined)
		}
	}
	if strings.Contains(joined, "ufw allow 24443") {
		t.Fatal("guide exposed the local panel port")
	}
}

func TestXHTTPConfigRejectsUnsafeValues(t *testing.T) {
	base, err := NewXHTTPConfig("vpn.example.com", "admin@example.com", "203.0.113.10", 24443)
	if err != nil {
		t.Fatal(err)
	}
	tests := []XHTTPConfig{}
	badDomain := base
	badDomain.Domain = "vpn.example.com;reboot"
	tests = append(tests, badDomain)
	badEmail := base
	badEmail.Email = "Admin <admin@example.com>"
	tests = append(tests, badEmail)
	badIP := base
	badIP.ServerIP = "127.0.0.1"
	tests = append(tests, badIP)
	privateIP := base
	privateIP.ServerIP = "10.0.0.10"
	tests = append(tests, privateIP)
	ipv6 := base
	ipv6.ServerIP = "2001:db8::10"
	tests = append(tests, ipv6)
	badPort := base
	badPort.PanelPort = 443
	tests = append(tests, badPort)
	badPath := base
	badPath.WebBasePath = "../../admin"
	tests = append(tests, badPath)
	badRelease := base
	badRelease.Release = "latest"
	tests = append(tests, badRelease)
	for _, value := range tests {
		if err := value.Validate(); err == nil {
			t.Fatalf("unsafe config accepted: %+v", value)
		}
	}
}

func TestCommandArgumentQuoting(t *testing.T) {
	if got := quoteCommandArgument("/tmp/key $(reboot)", "linux"); got != `'/tmp/key $(reboot)'` {
		t.Fatalf("unsafe display quoting: %q", got)
	}
	if got := quoteCommandArgument("/tmp/user's key", "linux"); got != `'/tmp/user'"'"'s key'` {
		t.Fatalf("single quote escaping: %q", got)
	}
	if got := quoteCommandArgument(`C:\Users\Admin User\id_ed25519`, "windows"); got != `'C:\Users\Admin User\id_ed25519'` {
		t.Fatalf("PowerShell quoting: %q", got)
	}
}

func TestDecodeXHTTPConfigIsStrict(t *testing.T) {
	value, err := NewXHTTPConfig("vpn.example.com", "admin@example.com", "203.0.113.10", 24443)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeXHTTPConfig(bytes.NewReader(data))
	if err != nil || decoded != value {
		t.Fatalf("decoded=%+v err=%v", decoded, err)
	}
	unknown := append(data[:len(data)-1], []byte(`,"command":"reboot"}`)...)
	if _, err := decodeXHTTPConfig(bytes.NewReader(unknown)); err == nil {
		t.Fatal("unknown JSON field accepted")
	}
	if _, err := decodeXHTTPConfig(strings.NewReader(string(data) + `{}`)); err == nil {
		t.Fatal("trailing JSON accepted")
	}
}
