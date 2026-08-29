//go:build linux

package workload

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"bastionctl/internal/report"
)

const (
	xuiRoot           = "/usr/local/x-ui"
	xuiCommand        = "/usr/bin/x-ui"
	xuiService        = "/etc/systemd/system/x-ui.service"
	xuiSecurityDropIn = "/etc/systemd/system/x-ui.service.d/10-bastionctl-security.conf"
	xuiEnvironment    = "/etc/default/x-ui"
	xuiDatabaseRoot   = "/etc/x-ui"
	xuiDatabase       = "/etc/x-ui/x-ui.db"
	xuiLogRoot        = "/var/log/x-ui"
	xhttpRenewalHook  = "/etc/letsencrypt/renewal-hooks/deploy/bastionctl-x-ui"
	xhttpBackupRoot   = "/var/backups/bastionctl/workloads/xhttp"
	xhttpMarkerSchema = "bastionctl.workload.xhttp.server.v1"
	maxReleaseBytes   = int64(200 << 20)
	maxExtractBytes   = int64(700 << 20)
)

type releaseAsset struct {
	URL    string
	SHA256 string
}

// Digests are copied from the published v3.7.0 release metadata and verified
// against both release assets. A tag or URL alone is not trusted: the runner
// refuses every other digest and verifies the complete archive before
// extracting a byte as root.
var xuiAssets = map[string]releaseAsset{
	"amd64": {
		URL:    "https://github.com/MHSanaei/3x-ui/releases/download/v3.7.0/x-ui-linux-amd64.tar.gz",
		SHA256: "0f8dd7baef3458f6591574e24814f322cf7f5e1e27f0a594683745e50be84ec5",
	},
	"arm64": {
		URL:    "https://github.com/MHSanaei/3x-ui/releases/download/v3.7.0/x-ui-linux-arm64.tar.gz",
		SHA256: "3caf1db1e8b10bb1fa1324c945522690bcf01c533ee75b377268f1c01a3ce896",
	},
}

type xhttpMarker struct {
	Schema      string      `json:"schema"`
	Config      XHTTPConfig `json:"config"`
	AssetSHA256 string      `json:"asset_sha256"`
	InstalledAt time.Time   `json:"installed_at"`
}

type tcpListener struct {
	Address string
	Port    int
	Owner   string
}

type ufwState struct {
	Active       bool
	DenyIncoming bool
	Allow80      bool
	Allow443     bool
	PanelExposed bool
}

type backupState struct {
	Directory  string
	Existing   map[string]bool
	WasActive  bool
	WasEnabled bool
}

var managedXHTTPPaths = []string{
	xuiRoot,
	xuiCommand,
	xuiService,
	xuiSecurityDropIn,
	xuiEnvironment,
	xuiDatabaseRoot,
	xuiLogRoot,
	XHTTPMarkerPath,
	XHTTPCredentialPath,
	xhttpRenewalHook,
}

const xuiSystemdSecurityPolicy = `[Service]
UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
`

const xuiEnvironmentPolicy = `# Managed by bastionctl. Local edits will be replaced.
XUI_DB_TYPE=sqlite
`

func runXHTTPPlatform(ctx context.Context, version, action string, cfg XHTTPConfig, yes bool, policy RuntimePolicy) *report.Report {
	r := report.New(version, "server", XHTTPReportAction(action), "localhost")
	switch action {
	case "plan":
		for _, result := range xhttpPreflight(ctx, cfg, policy) {
			r.Add(result)
		}
		if !r.HasFailures() {
			if _, markerErr := loadXHTTPMarker(); markerErr == nil {
				verification := report.New(version, "server", XHTTPReportAction("verify"), "localhost")
				verifyXHTTP(ctx, cfg, policy, verification)
				failures := failedControls(verification)
				if len(failures) == 0 {
					r.Add(report.Result{Control: "xhttp.install", Status: report.Pass, Severity: "critical", Message: "автоматическая часть XHTTP уже соответствует desired state; повторная установка не требуется"})
				} else {
					r.Add(report.Result{Control: "xhttp.install", Status: report.Planned, Severity: "critical", Message: "восстановить управляемую установку 3x-ui и повторно проверить её", Details: map[string]string{"repair_controls": strings.Join(failures, ",")}})
				}
			} else {
				r.Add(report.Result{
					Control: "xhttp.install", Status: report.Planned, Severity: "critical",
					Message: "установить проверенный 3x-ui, локальную панель, Certbot и сертификат; VLESS inbound останется ручным шагом",
					Details: map[string]string{"release": XHTTPRelease, "panel": "127.0.0.1:" + strconv.Itoa(cfg.PanelPort), "public": "80/tcp, 443/tcp"},
				})
			}
		}
	case "apply":
		if !yes {
			r.Add(report.Result{Control: "confirmation", Status: report.Fail, Severity: "critical", Message: "apply требует --yes"})
			return r
		}
		if os.Geteuid() != 0 {
			r.Add(report.Result{Control: "privileges", Status: report.Fail, Severity: "critical", Message: "установка XHTTP должна выполняться от root"})
			return r
		}
		for _, result := range xhttpPreflight(ctx, cfg, policy) {
			r.Add(result)
		}
		if r.HasFailures() {
			return r
		}
		if _, markerErr := loadXHTTPMarker(); markerErr == nil {
			verification := report.New(version, "server", XHTTPReportAction("verify"), "localhost")
			verifyXHTTP(ctx, cfg, policy, verification)
			if !verification.HasFailures() {
				for _, result := range verification.Results {
					if result.Status == report.Warn {
						r.Add(result)
					}
				}
				r.Add(report.Result{Control: "xhttp.install", Status: report.Pass, Severity: "critical", Message: "автоматическая часть XHTTP уже соответствует desired state; изменений нет"})
				return r
			}
		}
		applyXHTTP(ctx, cfg, policy, r)
	case "verify":
		verifyXHTTP(ctx, cfg, policy, r)
	}
	return r
}

func failedControls(value *report.Report) []string {
	result := []string{}
	for _, item := range value.Results {
		if item.Status == report.Fail {
			result = append(result, item.Control)
		}
	}
	sort.Strings(result)
	return result
}

func xhttpPreflight(ctx context.Context, cfg XHTTPConfig, policy RuntimePolicy) []report.Result {
	results := []report.Result{}
	if os.Geteuid() != 0 {
		results = append(results, report.Result{Control: "xhttp.privileges", Status: report.Fail, Severity: "critical", Message: "удалённый plan должен выполняться через ограниченный sudo"})
	}
	if err := verifySSHTunnelPolicy(ctx, cfg, policy); err != nil {
		results = append(results, report.Result{Control: "xhttp.ssh-tunnel", Status: report.Fail, Severity: "critical", Message: "узкий SSH-туннель панели не применён", Details: map[string]string{"error": err.Error()}})
	} else {
		results = append(results, report.Result{Control: "xhttp.ssh-tunnel", Status: report.Pass, Severity: "critical", Message: "администратору разрешён только local-forward к loopback-порту панели"})
	}

	osID, versionID, err := readOSRelease()
	if err != nil {
		results = append(results, report.Result{Control: "xhttp.os", Status: report.Fail, Severity: "critical", Message: err.Error()})
	} else if osID != "ubuntu" && osID != "debian" {
		results = append(results, report.Result{Control: "xhttp.os", Status: report.Fail, Severity: "critical", Message: "автоматическая установка поддерживает только Ubuntu/Debian", Details: map[string]string{"id": osID, "version": versionID}})
	} else {
		status := report.Pass
		message := "Ubuntu/Debian и systemd поддерживаются"
		if osID == "ubuntu" && versionID != "24.04" {
			status = report.Warn
			message = "руководство проверено на Ubuntu 24.04; текущий выпуск требует отдельной проверки"
		}
		if _, statErr := os.Stat("/run/systemd/system"); statErr != nil {
			status = report.Fail
			message = "systemd не обнаружен"
		}
		results = append(results, report.Result{Control: "xhttp.os", Status: status, Severity: "high", Message: message, Details: map[string]string{"id": osID, "version": versionID}})
	}

	asset, ok := xuiAssets[runtime.GOARCH]
	if !ok {
		results = append(results, report.Result{Control: "xhttp.architecture", Status: report.Fail, Severity: "critical", Message: "3x-ui разрешён только для Linux amd64/arm64", Details: map[string]string{"goarch": runtime.GOARCH}})
	} else {
		results = append(results, report.Result{Control: "xhttp.architecture", Status: report.Pass, Severity: "high", Message: "архитектура имеет закреплённый release asset", Details: map[string]string{"goarch": runtime.GOARCH, "sha256": asset.SHA256}})
	}

	if memory, memoryErr := totalMemoryBytes(); memoryErr != nil {
		results = append(results, report.Result{Control: "xhttp.capacity", Status: report.Warn, Severity: "medium", Message: "не удалось определить объём RAM", Details: map[string]string{"error": memoryErr.Error()}})
	} else {
		var stat syscall.Statfs_t
		diskErr := syscall.Statfs("/usr/local", &stat)
		disk := uint64(0)
		if diskErr == nil {
			disk = stat.Bavail * uint64(stat.Bsize)
		}
		status := report.Pass
		message := "ресурсы соответствуют рекомендациям"
		if memory < 1<<30 || (diskErr == nil && disk < 2<<30) {
			status = report.Fail
			message = "недостаточно RAM или свободного места для безопасной установки"
		} else if memory < 2<<30 || (diskErr == nil && disk < 10<<30) {
			status = report.Warn
			message = "ресурсы ниже рекомендации документации: 2 ГБ RAM и 10 ГБ диска"
		}
		details := map[string]string{"ram_bytes": strconv.FormatUint(memory, 10)}
		if diskErr == nil {
			details["free_bytes"] = strconv.FormatUint(disk, 10)
		} else {
			details["disk_error"] = diskErr.Error()
		}
		results = append(results, report.Result{Control: "xhttp.capacity", Status: status, Severity: "high", Message: message, Details: details})
	}

	dnsCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	addresses, dnsErr := net.DefaultResolver.LookupIPAddr(dnsCtx, cfg.Domain)
	cancel()
	if dnsErr != nil {
		results = append(results, report.Result{Control: "xhttp.dns", Status: report.Fail, Severity: "critical", Message: "домен пока не разрешается", Details: map[string]string{"domain": cfg.Domain, "error": dnsErr.Error()}})
	} else {
		expected := net.ParseIP(cfg.ServerIP)
		matched := false
		unexpected := []string{}
		resolved := make([]string, 0, len(addresses))
		for _, address := range addresses {
			resolved = append(resolved, address.IP.String())
			if address.IP.Equal(expected) {
				matched = true
			} else {
				unexpected = append(unexpected, address.IP.String())
			}
		}
		sort.Strings(resolved)
		sort.Strings(unexpected)
		status := report.Pass
		message := "DNS точно указывает на ожидаемый IP сервера"
		if !matched || len(unexpected) > 0 {
			status = report.Fail
			message = "DNS содержит отсутствующий или лишний A/AAAA-адрес; Let's Encrypt может попасть на неверный сервер"
		}
		results = append(results, report.Result{Control: "xhttp.dns", Status: status, Severity: "critical", Message: message, Details: map[string]string{"domain": cfg.Domain, "expected": cfg.ServerIP, "resolved": strings.Join(resolved, ","), "unexpected": strings.Join(unexpected, ",")}})
	}

	marker, markerErr := loadXHTTPMarker()
	managed := markerErr == nil
	if markerErr != nil && !os.IsNotExist(markerErr) {
		results = append(results, report.Result{Control: "xhttp.ownership", Status: report.Fail, Severity: "critical", Message: "маркер установленного сервиса повреждён", Details: map[string]string{"error": markerErr.Error()}})
	} else if !managed {
		unmanaged := existingPaths(managedXHTTPPaths...)
		if len(unmanaged) > 0 {
			results = append(results, report.Result{Control: "xhttp.ownership", Status: report.Fail, Severity: "critical", Message: "обнаружена существующая установка, не принадлежащая bastionctl; автоматическое принятие запрещено", Details: map[string]string{"paths": strings.Join(unmanaged, ",")}})
		} else {
			results = append(results, report.Result{Control: "xhttp.ownership", Status: report.Pass, Severity: "critical", Message: "конфликтующей установки 3x-ui не обнаружено"})
		}
	} else if marker.Config != cfg {
		results = append(results, report.Result{Control: "xhttp.ownership", Status: report.Fail, Severity: "critical", Message: "локальная конфигурация не совпадает с установленным workload; автоматическая миграция параметров пока запрещена"})
	} else {
		results = append(results, report.Result{Control: "xhttp.ownership", Status: report.Pass, Severity: "critical", Message: "существующая установка принадлежит bastionctl и может быть обновлена"})
	}

	listeners, listenerErr := listTCPListeners(ctx)
	if listenerErr != nil {
		results = append(results, report.Result{Control: "xhttp.ports", Status: report.Fail, Severity: "critical", Message: "не удалось проверить TCP listeners", Details: map[string]string{"error": listenerErr.Error()}})
	} else {
		busy := []string{}
		for _, port := range []int{XHTTPChallengePort, XHTTPPublicPort, cfg.PanelPort} {
			for _, listener := range listenersOnPort(listeners, port) {
				owned := managed && ((port == XHTTPPublicPort && listenerOwnedBy(listener, "xray")) ||
					(port == cfg.PanelPort && listenerOwnedBy(listener, "x-ui")))
				if port == XHTTPChallengePort || !owned {
					busy = append(busy, strconv.Itoa(port)+" ("+listener.Address+")")
				}
			}
		}
		status := report.Pass
		message := "порты 80, 443 и локальный порт панели готовы"
		if len(busy) > 0 {
			status = report.Fail
			message = "нужные порты уже заняты посторонним listener"
		}
		results = append(results, report.Result{Control: "xhttp.ports", Status: status, Severity: "critical", Message: message, Details: map[string]string{"busy": strings.Join(busy, ",")}})
	}

	ufwOutput, commandErr := runCommand(ctx, "ufw", "status", "verbose")
	if commandErr != nil {
		results = append(results, report.Result{Control: "xhttp.firewall", Status: report.Fail, Severity: "critical", Message: "UFW недоступен; сначала примените базовую политику bastionctl", Details: map[string]string{"error": commandErr.Error()}})
	} else {
		state := parseUFWState(ufwOutput, cfg.PanelPort)
		status := report.Pass
		message := "UFW разрешает только публичные 80/443; панель не опубликована"
		switch {
		case !state.Active || !state.DenyIncoming:
			status = report.Fail
			message = "UFW должен быть активен с default deny incoming"
		case !state.Allow80 || !state.Allow443:
			status = report.Fail
			message = "в UFW отсутствует явное разрешение TCP 80/443; обновите и примените политику"
		case state.PanelExposed:
			status = report.Fail
			message = "локальный порт панели опубликован в UFW; удалите это правило"
		}
		results = append(results, report.Result{Control: "xhttp.firewall", Status: status, Severity: "critical", Message: message})
	}

	if ok {
		probeCtx, probeCancel := context.WithTimeout(ctx, 20*time.Second)
		probeErr := probeRelease(probeCtx, asset.URL)
		probeCancel()
		if probeErr != nil {
			results = append(results, report.Result{Control: "xhttp.release", Status: report.Fail, Severity: "high", Message: "сервер не может получить закреплённый релиз 3x-ui", Details: map[string]string{"error": probeErr.Error()}})
		} else {
			results = append(results, report.Result{Control: "xhttp.release", Status: report.Pass, Severity: "high", Message: "закреплённый release asset доступен по HTTPS", Details: map[string]string{"release": XHTTPRelease}})
		}
	}
	return results
}

func verifySSHTunnelPolicy(ctx context.Context, cfg XHTTPConfig, policy RuntimePolicy) error {
	if policy.AdminUser == "" || strings.ContainsAny(policy.AdminUser, ",=\r\n\x00") {
		return fmt.Errorf("admin_user отсутствует или недопустим")
	}
	expected := XHTTPPanelDestination(cfg)
	configured := false
	wantedPermitOpen := make([]string, 0, len(policy.SSHLocalForwardDestinations))
	for _, destination := range policy.SSHLocalForwardDestinations {
		host, port, err := net.SplitHostPort(destination)
		if err != nil || host != "127.0.0.1" {
			return fmt.Errorf("недопустимое назначение local-forward %q", destination)
		}
		if _, err := strconv.Atoi(port); err != nil {
			return fmt.Errorf("недопустимый порт local-forward %q", destination)
		}
		wantedPermitOpen = append(wantedPermitOpen, destination)
		if port == strconv.Itoa(cfg.PanelPort) {
			configured = true
		}
	}
	if !configured {
		return fmt.Errorf("в серверной политике отсутствует PermitOpen %s", expected)
	}
	wantedPermitOpen = sortedUniqueStrings(wantedPermitOpen)
	output, err := runCommand(ctx, "sshd", "-T", "-C", "user="+policy.AdminUser+",host=localhost,addr=127.0.0.1")
	if err != nil {
		return fmt.Errorf("sshd -T: %w (%s)", err, output)
	}
	allow := ""
	permitOpen := []string{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "allowtcpforwarding":
			allow = fields[1]
		case "permitopen":
			permitOpen = append(permitOpen, fields[1:]...)
		}
	}
	if allow != "local" {
		return fmt.Errorf("allowtcpforwarding=%q, ожидается local", allow)
	}
	permitOpen = sortedUniqueStrings(permitOpen)
	if strings.Join(permitOpen, " ") != strings.Join(wantedPermitOpen, " ") {
		return fmt.Errorf("эффективный PermitOpen=%q, ожидается точный список %q", strings.Join(permitOpen, " "), strings.Join(wantedPermitOpen, " "))
	}
	return nil
}

func sortedUniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
