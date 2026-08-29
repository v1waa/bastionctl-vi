//go:build linux

package workload

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"bastionctl/internal/report"
)

func TestParseUFWState(t *testing.T) {
	output := `Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)

To                         Action      From
--                         ------      ----
80/tcp                     ALLOW IN    Anywhere
443/tcp                    ALLOW IN    Anywhere
22/tcp                     ALLOW IN    Anywhere
`
	state := parseUFWState(output, 24443)
	if !state.Active || !state.DenyIncoming || !state.Allow80 || !state.Allow443 || state.PanelExposed {
		t.Fatalf("unexpected state: %+v", state)
	}
	state = parseUFWState(output+"24443/tcp                  ALLOW IN    Anywhere\n", 24443)
	if !state.PanelExposed {
		t.Fatal("public panel rule was not detected")
	}
	restricted := parseUFWState(`Status: active
Default: deny (incoming), allow (outgoing), disabled (routed)
80/tcp ALLOW IN 192.0.2.10
443/tcp ALLOW IN 192.0.2.10
`, 24443)
	if restricted.Allow80 || restricted.Allow443 {
		t.Fatalf("restricted rules treated as public ACME/service access: %+v", restricted)
	}
	v6 := parseUFWState(`Status: active
Default: deny (incoming), allow (outgoing), disabled (routed)
80/tcp (v6) ALLOW IN Anywhere (v6)
443/tcp (v6) ALLOW IN Anywhere (v6)
20000:30000/tcp ALLOW IN 192.0.2.10
`, 24443)
	if !v6.Allow80 || !v6.Allow443 || !v6.PanelExposed {
		t.Fatalf("IPv6/range rules were not parsed: %+v", v6)
	}
}

func TestParseTCPListeners(t *testing.T) {
	listeners := parseTCPListeners("LISTEN 0 4096 127.0.0.1:24443 0.0.0.0:* users:((\"x-ui\",pid=11,fd=7))\nLISTEN 0 4096 [::]:443 [::]:* users:((\"xray-linux-amd64\",pid=12,fd=8))\n")
	if len(listeners) != 2 || listeners[0].Address != "127.0.0.1" || listeners[0].Port != 24443 || listeners[1].Address != "::" || listeners[1].Port != 443 {
		t.Fatalf("listeners=%+v", listeners)
	}
	if !isLoopbackAddress(listeners[0].Address) || isLoopbackAddress(listeners[1].Address) {
		t.Fatalf("loopback classification failed: %+v", listeners)
	}
	if !listenerOwnedBy(listeners[0], "x-ui") || !listenerOwnedBy(listeners[1], "xray") {
		t.Fatalf("listener owners were not parsed: %+v", listeners)
	}
}

func TestExtractReleaseRejectsLinksAndTraversal(t *testing.T) {
	for _, test := range []struct {
		name   string
		header tar.Header
	}{
		{name: "symlink", header: tar.Header{Name: "x-ui/link", Typeflag: tar.TypeSymlink, Linkname: "/etc/shadow"}},
		{name: "traversal", header: tar.Header{Name: "x-ui/../../etc/shadow", Typeflag: tar.TypeReg, Mode: 0o600, Size: 1}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var archive bytes.Buffer
			zipper := gzip.NewWriter(&archive)
			writer := tar.NewWriter(zipper)
			if err := writer.WriteHeader(&test.header); err != nil {
				t.Fatal(err)
			}
			if test.header.Size > 0 {
				_, _ = writer.Write([]byte("x"))
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			if err := zipper.Close(); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "release.tar.gz")
			if err := os.WriteFile(path, archive.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := extractRelease(path, t.TempDir()); err == nil {
				t.Fatal("unsafe archive entry accepted")
			}
		})
	}
}

func TestReleaseAllowlistAndPaths(t *testing.T) {
	if !allowedReleaseHost("github.com") || !allowedReleaseHost("release-assets.githubusercontent.com") || allowedReleaseHost("github.com.evil.example") {
		t.Fatal("release host allowlist is incorrect")
	}
	if !pathWithin("/safe/root", "/safe/root/file") || pathWithin("/safe/root", "/safe/other") {
		t.Fatal("path containment is incorrect")
	}
	for arch, asset := range xuiAssets {
		if len(asset.SHA256) != 64 || asset.URL == "" {
			t.Fatalf("asset %s is incomplete: %+v", arch, asset)
		}
	}
}

func TestMissingSystemdUnitClassification(t *testing.T) {
	for _, value := range []string{
		"Unit x-ui.service could not be found.",
		"Unit x-ui.service not loaded.",
	} {
		if !missingSystemdUnit(value) {
			t.Fatalf("missing unit was not recognized: %q", value)
		}
	}
	if missingSystemdUnit("Job for x-ui.service failed") {
		t.Fatal("real service failure was ignored")
	}
}

func TestVerifySSHTunnelPolicyIsDestinationBound(t *testing.T) {
	directory := t.TempDir()
	sshd := filepath.Join(directory, "sshd")
	content := "#!/bin/sh\nprintf '%s\\n' 'allowtcpforwarding local' \"${BASTIONCTL_TEST_PERMITOPEN:-permitopen 127.0.0.1:24443}\"\n"
	if err := os.WriteFile(sshd, []byte(content), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
	cfg, err := NewXHTTPConfig("vpn.example.com", "admin@example.com", "203.0.113.10", 24443)
	if err != nil {
		t.Fatal(err)
	}
	policy := RuntimePolicy{AdminUser: "operator", SSHLocalForwardDestinations: []string{"127.0.0.1:24443"}}
	if err := verifySSHTunnelPolicy(context.Background(), cfg, policy); err != nil {
		t.Fatal(err)
	}
	policy.SSHLocalForwardDestinations = []string{"127.0.0.1:25554"}
	if err := verifySSHTunnelPolicy(context.Background(), cfg, policy); err == nil {
		t.Fatal("mismatched PermitOpen policy accepted")
	}
	policy.SSHLocalForwardDestinations = []string{"127.0.0.1:24443"}
	t.Setenv("BASTIONCTL_TEST_PERMITOPEN", "permitopen 127.0.0.1:24443 example.com:443")
	if err := verifySSHTunnelPolicy(context.Background(), cfg, policy); err == nil {
		t.Fatal("unexpected extra PermitOpen destination accepted")
	}
}

func TestVerifyXUIServiceSandbox(t *testing.T) {
	directory := t.TempDir()
	systemctl := filepath.Join(directory, "systemctl")
	content := "#!/bin/sh\nprintf '%s\\n' 'UMask=0077' 'NoNewPrivileges=yes' 'PrivateTmp=yes' 'ProtectHome=yes' 'ProtectKernelTunables=yes' 'ProtectKernelModules=yes' 'ProtectControlGroups=yes' 'RestrictSUIDSGID=yes'\n"
	if err := os.WriteFile(systemctl, []byte(content), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
	if err := verifyXUIServiceSandbox(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(xuiSystemdSecurityPolicy, "NoNewPrivileges=yes") || !strings.Contains(xuiSystemdSecurityPolicy, "UMask=0077") {
		t.Fatal("systemd security policy is incomplete")
	}
	if xuiEnvironmentPolicy != "# Managed by bastionctl. Local edits will be replaced.\nXUI_DB_TYPE=sqlite\n" {
		t.Fatal("x-ui environment is not deterministic SQLite policy")
	}
}

func TestFailedControlsReturnsOnlySortedFailures(t *testing.T) {
	value := report.New("test", "server", "workload.xhttp.verify", "localhost")
	value.Add(report.Result{Control: "xhttp.zeta", Status: report.Fail})
	value.Add(report.Result{Control: "xhttp.warning", Status: report.Warn})
	value.Add(report.Result{Control: "xhttp.alpha", Status: report.Fail})
	value.Add(report.Result{Control: "xhttp.pass", Status: report.Pass})

	got := failedControls(value)
	if strings.Join(got, ",") != "xhttp.alpha,xhttp.zeta" {
		t.Fatalf("failed controls=%v", got)
	}
}
