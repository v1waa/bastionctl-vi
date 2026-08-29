//go:build linux

package workload

import (
	"context"
	"encoding/json"
	"os"
	"runtime"
	"strconv"
	"time"

	"bastionctl/internal/report"
)

func applyXHTTP(ctx context.Context, cfg XHTTPConfig, policy RuntimePolicy, r *report.Report) {
	asset := xuiAssets[runtime.GOARCH]
	if output, err := runCommand(ctx, "apt-get", "update"); err != nil {
		r.Add(commandFailure("xhttp.packages", "apt-get update завершился с ошибкой", output, err))
		return
	}
	if output, err := runCommand(ctx, "apt-get", "install", "-y", "--no-install-recommends", "ca-certificates", "certbot"); err != nil {
		r.Add(commandFailure("xhttp.packages", "не удалось установить системный Certbot", output, err))
		return
	}
	r.Add(report.Result{Control: "xhttp.packages", Status: report.Changed, Severity: "high", Message: "системные зависимости и Certbot проверены", Changed: true})

	archivePath, err := downloadRelease(ctx, asset)
	if err != nil {
		r.Add(report.Result{Control: "xhttp.download", Status: report.Fail, Severity: "critical", Message: "не удалось безопасно получить 3x-ui", Details: map[string]string{"error": err.Error()}})
		return
	}
	defer os.Remove(archivePath)
	stageRoot, err := os.MkdirTemp("/usr/local", ".bastionctl-xui-stage-")
	if err != nil {
		r.Add(report.Result{Control: "xhttp.stage", Status: report.Fail, Severity: "critical", Message: err.Error()})
		return
	}
	defer os.RemoveAll(stageRoot)
	if err := extractRelease(archivePath, stageRoot); err != nil {
		r.Add(report.Result{Control: "xhttp.stage", Status: report.Fail, Severity: "critical", Message: "release archive отклонён", Details: map[string]string{"error": err.Error()}})
		return
	}
	if err := validateStagedRelease(stageRoot); err != nil {
		r.Add(report.Result{Control: "xhttp.stage", Status: report.Fail, Severity: "critical", Message: "содержимое release archive не прошло проверку", Details: map[string]string{"error": err.Error()}})
		return
	}
	r.Add(report.Result{Control: "xhttp.download", Status: report.Pass, Severity: "critical", Message: "архив 3x-ui полностью проверен до распаковки", Details: map[string]string{"release": XHTTPRelease, "sha256": asset.SHA256}})

	_, markerErr := loadXHTTPMarker()
	managedBefore := markerErr == nil
	backup, err := createXHTTPBackup(ctx, managedBefore)
	if err != nil {
		r.Add(report.Result{Control: "xhttp.backup", Status: report.Fail, Severity: "critical", Message: "не удалось создать резервную копию", Details: map[string]string{"error": err.Error()}})
		return
	}
	r.BackupDir = backup.Directory
	r.Add(report.Result{Control: "xhttp.backup", Status: report.Pass, Severity: "critical", Message: "резервная копия управляемых файлов создана", Details: map[string]string{"path": backup.Directory}})

	committed := false
	defer func() {
		if committed {
			return
		}
		rollbackCtx, cancelRollback := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancelRollback()
		if rollbackErr := restoreXHTTPBackup(rollbackCtx, backup); rollbackErr != nil {
			r.Add(report.Result{Control: "xhttp.rollback", Status: report.Fail, Severity: "critical", Message: "автоматический откат завершился с ошибкой", Details: map[string]string{"error": rollbackErr.Error(), "backup": backup.Directory}})
		} else {
			r.Add(report.Result{Control: "xhttp.rollback", Status: report.Changed, Severity: "critical", Message: "изменения XHTTP откачены после ошибки", Changed: true, Details: map[string]string{"backup": backup.Directory}})
			r.Warnings = append(r.Warnings, "общие системные пакеты Certbot/CA и состояние Let's Encrypt не удаляются автоматически, чтобы не повредить другие сервисы")
		}
	}()

	_, _ = runCommand(ctx, "systemctl", "stop", "x-ui.service")
	if err := replaceXUIFiles(stageRoot); err != nil {
		r.Add(report.Result{Control: "xhttp.install", Status: report.Fail, Severity: "critical", Message: "не удалось установить файлы 3x-ui", Details: map[string]string{"error": err.Error()}})
		return
	}

	credentialsCreated := false
	if !managedBefore {
		if err := ensurePrivateWorkloadDirectory(); err != nil {
			r.Add(report.Result{Control: "xhttp.credentials", Status: report.Fail, Severity: "critical", Message: "не удалось защитить каталог workload", Details: map[string]string{"error": err.Error()}})
			return
		}
		username, randomErr := secureCredential("bastion", 6)
		if randomErr != nil {
			r.Add(report.Result{Control: "xhttp.credentials", Status: report.Fail, Severity: "critical", Message: randomErr.Error()})
			return
		}
		password, randomErr := secureCredential("", 18)
		if randomErr != nil {
			r.Add(report.Result{Control: "xhttp.credentials", Status: report.Fail, Severity: "critical", Message: randomErr.Error()})
			return
		}
		if output, commandErr := runXUI(ctx, "setting", "-port", strconv.Itoa(cfg.PanelPort), "-username", username, "-password", password, "-webBasePath", cfg.WebBasePath, "-listenIP", "127.0.0.1"); commandErr != nil {
			r.Add(commandFailure("xhttp.panel", "3x-ui не принял безопасные начальные настройки", output, commandErr))
			return
		}
		access := "# One-time 3x-ui credentials generated by bastionctl.\n" +
			"# Save the password in a password manager, enable 2FA, then delete this file.\n" +
			"PANEL_URL=http://127.0.0.1:" + strconv.Itoa(cfg.PanelPort) + "/" + cfg.WebBasePath + "/\n" +
			"PANEL_USERNAME=" + username + "\n" +
			"PANEL_PASSWORD=" + password + "\n"
		if err := atomicWriteFile(XHTTPCredentialPath, []byte(access), 0o600); err != nil {
			r.Add(report.Result{Control: "xhttp.credentials", Status: report.Fail, Severity: "critical", Message: "не удалось сохранить одноразовые данные панели", Details: map[string]string{"error": err.Error()}})
			return
		}
		credentialsCreated = true
	} else if output, commandErr := runXUI(ctx, "setting", "-port", strconv.Itoa(cfg.PanelPort), "-webBasePath", cfg.WebBasePath, "-listenIP", "127.0.0.1"); commandErr != nil {
		r.Add(commandFailure("xhttp.panel", "не удалось подтвердить локальные настройки панели", output, commandErr))
		return
	}
	if err := secureXUIState(); err != nil {
		r.Add(report.Result{Control: "xhttp.permissions", Status: report.Fail, Severity: "critical", Message: "не удалось защитить базу и журналы x-ui", Details: map[string]string{"error": err.Error()}})
		return
	}
	if err := verifyPanelSettings(ctx, cfg); err != nil {
		r.Add(report.Result{Control: "xhttp.panel", Status: report.Fail, Severity: "critical", Message: "проверка настроек панели не пройдена", Details: map[string]string{"error": err.Error()}})
		return
	}

	hook := "#!/bin/sh\nset -eu\nsystemctl try-restart x-ui.service >/dev/null 2>&1 || true\n"
	if err := atomicWriteFile(xhttpRenewalHook, []byte(hook), 0o700); err != nil {
		r.Add(report.Result{Control: "xhttp.certificate", Status: report.Fail, Severity: "critical", Message: "не удалось установить renewal hook", Details: map[string]string{"error": err.Error()}})
		return
	}
	certbotArgs := []string{"certonly", "--standalone", "--non-interactive", "--agree-tos", "--email", cfg.Email, "--domain", cfg.Domain, "--cert-name", cfg.Domain, "--preferred-challenges", "http", "--keep-until-expiring"}
	if output, commandErr := runCommand(ctx, "certbot", certbotArgs...); commandErr != nil {
		r.Add(commandFailure("xhttp.certificate", "Let's Encrypt не выдал сертификат; проверьте DNS и доступность TCP 80", output, commandErr))
		return
	}
	if err := verifyCertificate(cfg); err != nil {
		r.Add(report.Result{Control: "xhttp.certificate", Status: report.Fail, Severity: "critical", Message: "полученный сертификат не прошёл локальную проверку", Details: map[string]string{"error": err.Error()}})
		return
	}

	marker := xhttpMarker{Schema: xhttpMarkerSchema, Config: cfg, AssetSHA256: asset.SHA256, InstalledAt: time.Now().UTC()}
	markerData, err := json.MarshalIndent(marker, "", "  ")
	if err != nil {
		r.Add(report.Result{Control: "xhttp.marker", Status: report.Fail, Severity: "critical", Message: err.Error()})
		return
	}
	if err := ensurePrivateWorkloadDirectory(); err != nil {
		r.Add(report.Result{Control: "xhttp.marker", Status: report.Fail, Severity: "critical", Message: "не удалось защитить каталог workload", Details: map[string]string{"error": err.Error()}})
		return
	}
	if err := atomicWriteFile(XHTTPMarkerPath, append(markerData, '\n'), 0o600); err != nil {
		r.Add(report.Result{Control: "xhttp.marker", Status: report.Fail, Severity: "critical", Message: "не удалось сохранить ownership-маркер", Details: map[string]string{"error": err.Error()}})
		return
	}
	if output, commandErr := runCommand(ctx, "systemctl", "daemon-reload"); commandErr != nil {
		r.Add(commandFailure("xhttp.service", "systemd daemon-reload завершился с ошибкой", output, commandErr))
		return
	}
	if output, commandErr := runCommand(ctx, "systemctl", "enable", "--now", "x-ui.service"); commandErr != nil {
		r.Add(commandFailure("xhttp.service", "не удалось включить и запустить x-ui", output, commandErr))
		return
	}

	verification := report.New(r.ToolVersion, "server", r.Action, "localhost")
	verifyXHTTP(ctx, cfg, policy, verification)
	for _, result := range verification.Results {
		r.Add(result)
	}
	if verification.HasFailures() {
		return
	}
	committed = true
	credentialMessage := "учётные данные панели сохранены в root-only файле"
	if !credentialsCreated {
		credentialMessage = "существующие учётные данные панели сохранены без ротации"
	}
	r.Add(report.Result{Control: "xhttp.install", Status: report.Changed, Severity: "critical", Message: "3x-ui и TLS готовы; VLESS/XHTTP inbound создаётся пользователем в панели", Changed: true, Details: map[string]string{"release": XHTTPRelease, "panel": "127.0.0.1:" + strconv.Itoa(cfg.PanelPort), "credentials": credentialMessage}})
}
