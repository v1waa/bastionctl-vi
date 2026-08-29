package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestParseFlagsAndPositionals(t *testing.T) {
	parsed, err := parse([]string{"user@host", "--port=2222", "--json"}, map[string]bool{"--port": true, "--json": false})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.values["--port"] != "2222" || !parsed.booleans["--json"] || len(parsed.positionals) != 1 {
		t.Fatalf("unexpected parse result: %+v", parsed)
	}
}

func TestParseRejectsDuplicateFlag(t *testing.T) {
	_, err := parse([]string{"--json", "--json"}, map[string]bool{"--json": false})
	if err == nil {
		t.Fatal("duplicate flag should fail")
	}
}

func TestApplyRequiresConfirmation(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"admin", "apply", "ops@example.com"}, "test", strings.NewReader(""), &stdout, &stderr)
	if code != exitUsage || !strings.Contains(stderr.String(), "--yes") {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
}

func TestHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"help"}, "test", strings.NewReader(""), &stdout, &stderr); code != exitOK {
		t.Fatalf("code=%d", code)
	}
	if !strings.Contains(stdout.String(), "server audit") || !strings.Contains(stdout.String(), "admin doctor") || !strings.Contains(stdout.String(), "--password-bootstrap") || !strings.Contains(stdout.String(), "fleet bootstrap") || !strings.Contains(stdout.String(), "fleet user-add") || !strings.Contains(stdout.String(), "fleet reset-plan") || !strings.Contains(stdout.String(), "fleet xhttp-config") || !strings.Contains(stdout.String(), "server workload xhttp") {
		t.Fatalf("incomplete help: %s", stdout.String())
	}
}

func TestPasswordBootstrapFlagsAreActionScoped(t *testing.T) {
	add, ok := fleetSpecification("add")
	if !ok || add["--password-bootstrap"] || !add["--admin-user"] {
		t.Fatalf("unexpected add specification: %+v", add)
	}
	install, ok := fleetSpecification("install")
	if !ok || install["--interactive-sudo"] {
		t.Fatalf("unexpected install specification: %+v", install)
	}
	bootstrap, ok := fleetSpecification("bootstrap")
	if !ok || len(bootstrap) != 2 {
		t.Fatalf("unexpected bootstrap specification: %+v", bootstrap)
	}
	userAdd, ok := fleetSpecification("user-add")
	if !ok || !userAdd["--username"] || !userAdd["--public-key"] || userAdd["--yes"] || userAdd["--sudo"] {
		t.Fatalf("unexpected user-add specification: %+v", userAdd)
	}
	reset, ok := fleetSpecification("reset")
	if !ok || reset["--yes"] {
		t.Fatalf("unexpected reset specification: %+v", reset)
	}
	xhttpConfig, ok := fleetSpecification("xhttp-config")
	if !ok || !xhttpConfig["--domain"] || !xhttpConfig["--email"] || !xhttpConfig["--server-ip"] {
		t.Fatalf("unexpected xhttp-config specification: %+v", xhttpConfig)
	}
	xhttpApply, ok := fleetSpecification("xhttp-apply")
	if !ok || xhttpApply["--yes"] {
		t.Fatalf("unexpected xhttp-apply specification: %+v", xhttpApply)
	}
}

func TestFleetXHTTPConfigAndGuide(t *testing.T) {
	stateDir := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"fleet", "add", "vpn", "ops@203.0.113.10", "--state-dir", stateDir}, "test", strings.NewReader(""), &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("add code=%d stderr=%q", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	code = Run(context.Background(), []string{
		"fleet", "xhttp-config", "vpn", "--state-dir", stateDir,
		"--domain", "vpn.example.com", "--email", "admin@example.com", "--server-ip", "203.0.113.10", "--panel-port", "24443",
	}, "test", strings.NewReader(""), &stdout, &stderr)
	if code != exitOK || !strings.Contains(stdout.String(), "TCP 80/443") {
		t.Fatalf("config code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	code = Run(context.Background(), []string{"fleet", "xhttp-guide", "vpn", "--state-dir", stateDir}, "test", strings.NewReader(""), &stdout, &stderr)
	if code != exitOK || !strings.Contains(stdout.String(), "ssh -N -L 127.0.0.1:18080") || !strings.Contains(stdout.String(), "VLESS + TLS + XHTTP") {
		t.Fatalf("guide code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestFleetRegistryWorkflow(t *testing.T) {
	stateDir := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{
		"fleet", "add", "web-01", "ops@example.com", "--state-dir", stateDir,
		"--profile", "web", "--tcp-ports", "8443", "--ssh-cidrs", "203.0.113.7/32",
	}, "test", strings.NewReader(""), &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("add code=%d stderr=%q", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	code = Run(context.Background(), []string{"fleet", "list", "--state-dir", stateDir, "--json"}, "test", strings.NewReader(""), &stdout, &stderr)
	if code != exitOK || !strings.Contains(stdout.String(), `"id": "web-01"`) {
		t.Fatalf("list code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	code = Run(context.Background(), []string{"fleet", "configure", "web-01", "--state-dir", stateDir, "--profile", "wireguard"}, "test", strings.NewReader(""), &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("configure code=%d stderr=%q", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	code = Run(context.Background(), []string{"fleet", "remove", "web-01", "--state-dir", stateDir}, "test", strings.NewReader(""), &stdout, &stderr)
	if code != exitUsage || !strings.Contains(stderr.String(), "--yes") {
		t.Fatalf("remove confirmation code=%d stderr=%q", code, stderr.String())
	}
}

func TestInteractiveConsoleStarts(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"console", "--state-dir", t.TempDir()}, "test", strings.NewReader("0\n"), &stdout, &stderr)
	if code != exitOK || !strings.Contains(stdout.String(), "консоль администратора") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestActionSpecificFlagsAreRejected(t *testing.T) {
	for _, args := range [][]string{
		{"admin", "doctor", "--yes"},
		{"server", "audit", "--yes"},
		{"fleet", "list", "--yes"},
	} {
		var stdout, stderr bytes.Buffer
		if code := Run(context.Background(), args, "test", strings.NewReader(""), &stdout, &stderr); code != exitUsage {
			t.Fatalf("args=%v code=%d stderr=%q", args, code, stderr.String())
		}
	}
}

func TestFleetResetRequiresConfirmationBeforeConnection(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"fleet", "reset", "missing", "--state-dir", t.TempDir()}, "test", strings.NewReader(""), &stdout, &stderr)
	if code != exitUsage || !strings.Contains(stderr.String(), "--yes") {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
}
