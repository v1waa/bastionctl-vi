//go:build linux

package workload

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"bastionctl/internal/report"
)

func verifyXHTTP(ctx context.Context, cfg XHTTPConfig, policy RuntimePolicy, r *report.Report) {
	if err := verifySSHTunnelPolicy(ctx, cfg, policy); err != nil {
		r.Add(report.Result{Control: "xhttp.ssh-tunnel", Status: report.Fail, Severity: "critical", Message: "SSH-туннель панели не ограничен ожидаемым назначением", Details: map[string]string{"error": err.Error()}})
	} else {
		r.Add(report.Result{Control: "xhttp.ssh-tunnel", Status: report.Pass, Severity: "critical", Message: "SSH local-forward к loopback-панели подтверждён"})
	}
	marker, err := loadXHTTPMarker()
	if err != nil {
		r.Add(report.Result{Control: "xhttp.marker", Status: report.Fail, Severity: "critical", Message: "workload не установлен или marker повреждён", Details: map[string]string{"error": err.Error()}})
		return
	}
	asset, supported := xuiAssets[runtime.GOARCH]
	if !supported || marker.Config != cfg || marker.AssetSHA256 != asset.SHA256 {
		r.Add(report.Result{Control: "xhttp.marker", Status: report.Fail, Severity: "critical", Message: "установленное состояние не совпадает с ожидаемым"})
		return
	}
	r.Add(report.Result{Control: "xhttp.marker", Status: report.Pass, Severity: "high", Message: "ownership и закреплённый release подтверждены"})
	if err := verifyXUIStatePermissions(); err != nil {
		r.Add(report.Result{Control: "xhttp.permissions", Status: report.Fail, Severity: "critical", Message: "права базы или журналов x-ui небезопасны", Details: map[string]string{"error": err.Error()}})
	} else {
		r.Add(report.Result{Control: "xhttp.permissions", Status: report.Pass, Severity: "high", Message: "база и журналы x-ui принадлежат root и закрыты от других пользователей"})
	}
	if info, credentialErr := os.Lstat(XHTTPCredentialPath); credentialErr == nil {
		stat, owned := info.Sys().(*syscall.Stat_t)
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || !owned || stat.Uid != 0 || stat.Gid != 0 {
			r.Add(report.Result{Control: "xhttp.credentials", Status: report.Fail, Severity: "critical", Message: "файл начальных данных панели имеет небезопасный тип, владельца или права"})
		} else {
			r.Add(report.Result{Control: "xhttp.credentials", Status: report.Warn, Severity: "medium", Message: "одноразовый файл данных панели ещё существует; удалите его после входа и включения 2FA"})
		}
	} else if !os.IsNotExist(credentialErr) {
		r.Add(report.Result{Control: "xhttp.credentials", Status: report.Fail, Severity: "critical", Message: "не удалось проверить файл начальных данных панели", Details: map[string]string{"error": credentialErr.Error()}})
	}

	versionOutput, versionErr := runXUI(ctx, "-v")
	if versionErr != nil || strings.TrimSpace(versionOutput) != strings.TrimPrefix(XHTTPRelease, "v") {
		details := map[string]string{"expected": strings.TrimPrefix(XHTTPRelease, "v"), "actual": strings.TrimSpace(versionOutput)}
		if versionErr != nil {
			details["error"] = versionErr.Error()
		}
		r.Add(report.Result{Control: "xhttp.version", Status: report.Fail, Severity: "critical", Message: "версия 3x-ui не совпадает с закреплённой", Details: details})
	} else {
		r.Add(report.Result{Control: "xhttp.version", Status: report.Pass, Severity: "high", Message: "3x-ui " + XHTTPRelease + " подтверждён"})
	}

	activeOutput, activeErr := runCommand(ctx, "systemctl", "is-active", "x-ui.service")
	enabledOutput, enabledErr := runCommand(ctx, "systemctl", "is-enabled", "x-ui.service")
	if activeErr != nil || enabledErr != nil || strings.TrimSpace(activeOutput) != "active" || strings.TrimSpace(enabledOutput) != "enabled" {
		r.Add(report.Result{Control: "xhttp.service", Status: report.Fail, Severity: "critical", Message: "x-ui не active/enabled", Details: map[string]string{"active": strings.TrimSpace(activeOutput), "enabled": strings.TrimSpace(enabledOutput)}})
	} else {
		r.Add(report.Result{Control: "xhttp.service", Status: report.Pass, Severity: "critical", Message: "x-ui active и enabled"})
	}
	if err := verifyXUIServiceSandbox(ctx); err != nil {
		r.Add(report.Result{Control: "xhttp.service-sandbox", Status: report.Fail, Severity: "critical", Message: "systemd hardening x-ui не применён", Details: map[string]string{"error": err.Error()}})
	} else {
		r.Add(report.Result{Control: "xhttp.service-sandbox", Status: report.Pass, Severity: "high", Message: "systemd ограничивает privileges, tmp, home и kernel interfaces x-ui"})
	}

	listeners, listenerErr := listTCPListeners(ctx)
	if listenerErr != nil {
		r.Add(report.Result{Control: "xhttp.listeners", Status: report.Fail, Severity: "critical", Message: "не удалось проверить listeners", Details: map[string]string{"error": listenerErr.Error()}})
	} else {
		panelFound := false
		panelPublic := false
		panelOwned := false
		publicFound := false
		publicOwned := false
		for _, listener := range listeners {
			if listener.Port == cfg.PanelPort {
				panelFound = true
				if listenerOwnedBy(listener, "x-ui") {
					panelOwned = true
				}
				if !isLoopbackAddress(listener.Address) {
					panelPublic = true
				}
			}
			if listener.Port == XHTTPPublicPort {
				publicFound = true
				if listenerOwnedBy(listener, "xray") {
					publicOwned = true
				}
			}
		}
		switch {
		case !panelFound:
			r.Add(report.Result{Control: "xhttp.panel-listener", Status: report.Fail, Severity: "critical", Message: "локальная панель не слушает назначенный порт"})
		case panelPublic:
			r.Add(report.Result{Control: "xhttp.panel-listener", Status: report.Fail, Severity: "critical", Message: "панель доступна не только на loopback; публичная экспозиция запрещена"})
		case !panelOwned:
			r.Add(report.Result{Control: "xhttp.panel-listener", Status: report.Fail, Severity: "critical", Message: "порт локальной панели занят не процессом x-ui"})
		default:
			r.Add(report.Result{Control: "xhttp.panel-listener", Status: report.Pass, Severity: "critical", Message: "панель доступна только через loopback/SSH-туннель"})
		}
		if publicFound && publicOwned {
			r.Add(report.Result{Control: "xhttp.inbound", Status: report.Pass, Severity: "high", Message: "listener VLESS/XHTTP на TCP 443 обнаружен"})
		} else if publicFound {
			r.Add(report.Result{Control: "xhttp.inbound", Status: report.Fail, Severity: "critical", Message: "TCP 443 занят процессом, не распознанным как Xray"})
		} else {
			r.Add(report.Result{Control: "xhttp.inbound", Status: report.Warn, Severity: "high", Message: "TCP 443 пока не слушается: создайте VLESS + TLS + XHTTP inbound вручную в панели"})
		}
	}

	if err := verifyCertificate(cfg); err != nil {
		r.Add(report.Result{Control: "xhttp.certificate", Status: report.Fail, Severity: "critical", Message: "сертификат недействителен", Details: map[string]string{"error": err.Error()}})
	} else {
		r.Add(report.Result{Control: "xhttp.certificate", Status: report.Pass, Severity: "critical", Message: "сертификат Let's Encrypt подходит домену и не истекает в ближайшие 14 дней"})
	}

	ufwOutput, ufwErr := runCommand(ctx, "ufw", "status", "verbose")
	if ufwErr != nil {
		r.Add(report.Result{Control: "xhttp.firewall", Status: report.Fail, Severity: "critical", Message: "UFW недоступен", Details: map[string]string{"error": ufwErr.Error()}})
	} else {
		state := parseUFWState(ufwOutput, cfg.PanelPort)
		if !state.Active || !state.DenyIncoming || !state.Allow80 || !state.Allow443 || state.PanelExposed {
			r.Add(report.Result{Control: "xhttp.firewall", Status: report.Fail, Severity: "critical", Message: "firewall не соответствует XHTTP-политике"})
		} else {
			r.Add(report.Result{Control: "xhttp.firewall", Status: report.Pass, Severity: "critical", Message: "наружу разрешены 80/443, порт панели не опубликован"})
		}
	}
}

func readOSRelease() (string, string, error) {
	file, err := os.Open("/etc/os-release")
	if err != nil {
		return "", "", fmt.Errorf("прочитать /etc/os-release: %w", err)
	}
	defer file.Close()
	values := map[string]string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, raw, ok := strings.Cut(scanner.Text(), "=")
		if !ok {
			continue
		}
		value, unquoteErr := strconv.Unquote(raw)
		if unquoteErr != nil {
			value = raw
		}
		values[key] = value
	}
	if err := scanner.Err(); err != nil {
		return "", "", err
	}
	if values["ID"] == "" {
		return "", "", errors.New("/etc/os-release не содержит ID")
	}
	return strings.ToLower(values["ID"]), values["VERSION_ID"], nil
}

func totalMemoryBytes() (uint64, error) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && fields[0] == "MemTotal:" {
			value, parseErr := strconv.ParseUint(fields[1], 10, 64)
			return value * 1024, parseErr
		}
	}
	return 0, errors.New("MemTotal не найден")
}

func runCommand(ctx context.Context, name string, args ...string) (string, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("%s не найден в PATH", name)
	}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C", "DEBIAN_FRONTEND=noninteractive")
	output, commandErr := cmd.CombinedOutput()
	value := strings.TrimSpace(string(output))
	if len(value) > 8000 {
		value = value[len(value)-8000:]
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return value, context.DeadlineExceeded
	}
	return value, commandErr
}

func runXUI(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, filepath.Join(xuiRoot, "x-ui"), args...)
	cmd.Dir = xuiRoot
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	output, err := cmd.CombinedOutput()
	value := strings.TrimSpace(string(output))
	if len(value) > 8000 {
		value = value[len(value)-8000:]
	}
	return value, err
}

func commandFailure(control, message, output string, err error) report.Result {
	details := map[string]string{"error": err.Error()}
	if output != "" {
		details["output"] = output
	}
	return report.Result{Control: control, Status: report.Fail, Severity: "critical", Message: message, Details: details}
}

func probeRelease(ctx context.Context, url string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return err
	}
	response, err := releaseHTTPClient().Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d", response.StatusCode)
	}
	return nil
}

func releaseHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Minute,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) > 8 {
				return errors.New("слишком много HTTP redirects")
			}
			if request.URL.Scheme != "https" || !allowedReleaseHost(request.URL.Hostname()) {
				return errors.New("release redirect ведёт на недоверенный адрес")
			}
			return nil
		},
	}
}

func allowedReleaseHost(host string) bool {
	host = strings.ToLower(host)
	return host == "github.com" || host == "release-assets.githubusercontent.com" || host == "objects.githubusercontent.com" || strings.HasSuffix(host, ".githubusercontent.com")
}

func downloadRelease(ctx context.Context, asset releaseAsset) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, asset.URL, nil)
	if err != nil {
		return "", err
	}
	response, err := releaseHTTPClient().Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("release download: HTTP %d", response.StatusCode)
	}
	if response.ContentLength > maxReleaseBytes {
		return "", errors.New("release archive превышает допустимый размер")
	}
	file, err := os.CreateTemp("/var/tmp", "bastionctl-xui-*.tar.gz")
	if err != nil {
		return "", err
	}
	path := file.Name()
	cleanup := true
	defer func() {
		file.Close()
		if cleanup {
			os.Remove(path)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return "", err
	}
	digest := sha256.New()
	written, err := io.Copy(io.MultiWriter(file, digest), io.LimitReader(response.Body, maxReleaseBytes+1))
	if err != nil {
		return "", err
	}
	if written <= 0 || written > maxReleaseBytes {
		return "", errors.New("release archive пуст или слишком велик")
	}
	actual := hex.EncodeToString(digest.Sum(nil))
	if actual != asset.SHA256 {
		return "", fmt.Errorf("SHA-256 не совпал: %s", actual)
	}
	if err := file.Sync(); err != nil {
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	cleanup = false
	return path, nil
}

func extractRelease(archivePath, destination string) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer file.Close()
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gzipReader.Close()
	tape := tar.NewReader(gzipReader)
	count := 0
	total := int64(0)
	for {
		header, nextErr := tape.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return nextErr
		}
		count++
		if count > 256 {
			return errors.New("слишком много файлов в release archive")
		}
		name := filepath.ToSlash(filepath.Clean(header.Name))
		if name == "." || name == "x-ui" {
			continue
		}
		if !strings.HasPrefix(name, "x-ui/") || filepath.IsAbs(header.Name) || strings.Contains(name, "../") {
			return fmt.Errorf("небезопасный путь в archive: %q", header.Name)
		}
		target := filepath.Join(destination, filepath.FromSlash(name))
		if !pathWithin(destination, target) {
			return fmt.Errorf("путь archive вышел за staging: %q", header.Name)
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if header.Size < 0 || header.Size > maxExtractBytes-total {
				return errors.New("release archive превышает лимит распаковки")
			}
			total += header.Size
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			mode := fs.FileMode(0o644)
			if header.Mode&0o111 != 0 {
				mode = 0o755
			}
			output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
			if err != nil {
				return err
			}
			copied, copyErr := io.CopyN(output, tape, header.Size)
			closeErr := output.Close()
			if copyErr != nil || copied != header.Size {
				return errors.Join(copyErr, errors.New("неполный файл в release archive"))
			}
			if closeErr != nil {
				return closeErr
			}
		default:
			return fmt.Errorf("release archive содержит запрещённый тип %d для %q", header.Typeflag, header.Name)
		}
	}
	return nil
}

func validateStagedRelease(stageRoot string) error {
	required := []string{
		filepath.Join(stageRoot, "x-ui", "x-ui"),
		filepath.Join(stageRoot, "x-ui", "x-ui.sh"),
		filepath.Join(stageRoot, "x-ui", "x-ui.service.debian"),
		filepath.Join(stageRoot, "x-ui", "bin", "xray-linux-"+runtime.GOARCH),
	}
	for _, path := range required {
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() == 0 {
			return fmt.Errorf("обязательный файл отсутствует или небезопасен: %s", path)
		}
	}
	for _, path := range []string{required[0], required[1], required[3]} {
		if err := os.Chmod(path, 0o755); err != nil {
			return err
		}
	}
	return nil
}

func replaceXUIFiles(stageRoot string) error {
	if err := removeManagedPath(xuiRoot); err != nil {
		return err
	}
	if err := os.Rename(filepath.Join(stageRoot, "x-ui"), xuiRoot); err != nil {
		return err
	}
	if err := atomicCopyFile(filepath.Join(xuiRoot, "x-ui.sh"), xuiCommand, 0o755); err != nil {
		return err
	}
	if err := atomicCopyFile(filepath.Join(xuiRoot, "x-ui.service.debian"), xuiService, 0o644); err != nil {
		return err
	}
	if err := atomicWriteFile(xuiSecurityDropIn, []byte(xuiSystemdSecurityPolicy), 0o644); err != nil {
		return err
	}
	if err := atomicWriteFile(xuiEnvironment, []byte(xuiEnvironmentPolicy), 0o600); err != nil {
		return err
	}
	return nil
}

func verifyXUIServiceSandbox(ctx context.Context) error {
	output, err := runCommand(ctx, "systemctl", "show", "x-ui.service",
		"--property=UMask", "--property=NoNewPrivileges", "--property=PrivateTmp",
		"--property=ProtectHome", "--property=ProtectKernelTunables",
		"--property=ProtectKernelModules", "--property=ProtectControlGroups",
		"--property=RestrictSUIDSGID")
	if err != nil {
		return fmt.Errorf("systemctl show: %w (%s)", err, output)
	}
	values := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok {
			values[key] = value
		}
	}
	expected := map[string]string{
		"UMask": "0077", "NoNewPrivileges": "yes", "PrivateTmp": "yes",
		"ProtectHome": "yes", "ProtectKernelTunables": "yes",
		"ProtectKernelModules": "yes", "ProtectControlGroups": "yes",
		"RestrictSUIDSGID": "yes",
	}
	for key, wanted := range expected {
		if values[key] != wanted {
			return fmt.Errorf("%s=%q, ожидается %q", key, values[key], wanted)
		}
	}
	return nil
}

func verifyPanelSettings(ctx context.Context, cfg XHTTPConfig) error {
	settings, err := runXUI(ctx, "setting", "-show", "true", "-getListen", "true")
	if err != nil {
		return err
	}
	if !strings.Contains(settings, "port: "+strconv.Itoa(cfg.PanelPort)) {
		return errors.New("панель не подтвердила назначенный порт")
	}
	if !strings.Contains(settings, "webBasePath: /"+cfg.WebBasePath) && !strings.Contains(settings, "webBasePath: "+cfg.WebBasePath) {
		return errors.New("панель не подтвердила web base path")
	}
	if !strings.Contains(settings, "listenIP: 127.0.0.1") {
		return errors.New("панель не подтвердила loopback listenIP")
	}
	return nil
}

func secureCredential(prefix string, bytesCount int) (string, error) {
	value := make([]byte, bytesCount)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(value), nil
}

func verifyCertificate(cfg XHTTPConfig) error {
	resolved, err := filepath.EvalSymlinks(cfg.CertificatePath())
	if err != nil {
		return err
	}
	archiveRoot := filepath.Join("/etc/letsencrypt/archive", cfg.Domain)
	if !pathWithin(archiveRoot, resolved) {
		return errors.New("certificate symlink ведёт за пределы ожидаемого Let's Encrypt archive")
	}
	data, err := os.ReadFile(resolved)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("PEM certificate не найден")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	if err := certificate.VerifyHostname(cfg.Domain); err != nil {
		return err
	}
	if time.Until(certificate.NotAfter) < 14*24*time.Hour {
		return fmt.Errorf("сертификат истекает %s", certificate.NotAfter.UTC().Format(time.RFC3339))
	}
	keyResolved, err := filepath.EvalSymlinks(cfg.PrivateKeyPath())
	if err != nil {
		return err
	}
	if !pathWithin(archiveRoot, keyResolved) {
		return errors.New("private key symlink ведёт за пределы ожидаемого Let's Encrypt archive")
	}
	keyInfo, err := os.Stat(keyResolved)
	if err != nil || !keyInfo.Mode().IsRegular() || keyInfo.Size() == 0 {
		return errors.New("private key отсутствует или пуст")
	}
	if keyInfo.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("private key имеет слишком широкие права %04o", keyInfo.Mode().Perm())
	}
	if stat, ok := keyInfo.Sys().(*syscall.Stat_t); !ok || stat.Uid != 0 {
		return errors.New("private key должен принадлежать root")
	}
	return nil
}

func loadXHTTPMarker() (xhttpMarker, error) {
	data, err := readRegularFile(XHTTPMarkerPath, 1<<20)
	if err != nil {
		return xhttpMarker{}, err
	}
	var marker xhttpMarker
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&marker); err != nil {
		return xhttpMarker{}, err
	}
	if marker.Schema != xhttpMarkerSchema {
		return xhttpMarker{}, errors.New("неподдерживаемая схема marker")
	}
	if err := marker.Config.Validate(); err != nil {
		return xhttpMarker{}, err
	}
	asset, ok := xuiAssets[runtime.GOARCH]
	if !ok || marker.AssetSHA256 != asset.SHA256 {
		return xhttpMarker{}, errors.New("marker содержит неизвестный release digest")
	}
	return marker, nil
}
