package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"bastionctl/internal/config"
	"bastionctl/internal/report"
	"bastionctl/internal/workload"
)

func RunWorkload(ctx context.Context, cfg config.AdminConfig, version string, connection Options, module, action string, request workload.XHTTPConfig, yes bool) *report.Report {
	reportAction := "workload-" + module + "-" + action
	r := report.New(version, "admin", reportAction, connection.Target)
	if err := validateConnection(connection); err != nil {
		r.Add(report.Result{Control: "connection", Status: report.Fail, Severity: "critical", Message: err.Error()})
		return r
	}
	if module != workload.XHTTPModule || !workload.IsXHTTPAction(action) {
		r.Add(report.Result{Control: "request", Status: report.Fail, Severity: "critical", Message: "неизвестный workload или action"})
		return r
	}
	if action == "apply" && !yes {
		r.Add(report.Result{Control: "confirmation", Status: report.Fail, Severity: "critical", Message: "workload apply требует отдельный plan и подтверждение"})
		return r
	}
	if err := request.Validate(); err != nil {
		r.Add(report.Result{Control: "request", Status: report.Fail, Severity: "critical", Message: err.Error()})
		return r
	}
	payload, err := json.Marshal(request)
	if err != nil {
		r.Add(report.Result{Control: "request", Status: report.Fail, Severity: "critical", Message: err.Error()})
		return r
	}
	parts := []string{"sudo", "-n", cfg.RemoteExecutable, "server", "workload", module, action, "--config", cfg.RemoteConfig, "--json"}
	if action == "apply" {
		parts = append(parts, "--yes")
	}
	connection.Action = reportAction
	stdout, stderr, commandErr := runRawSSHInput(ctx, cfg, connection, remoteCommand(parts), bytes.NewReader(append(payload, '\n')), 30*time.Minute)
	remote, reportErr := decodeRemoteReport(stdout, reportAction)
	if reportErr == nil {
		r.Results = append(r.Results, remote.Results...)
		r.Warnings = append(r.Warnings, remote.Warnings...)
		r.BackupDir = remote.BackupDir
		if remote.ToolVersion != version {
			r.Warnings = append(r.Warnings, fmt.Sprintf("локальная версия %s, серверная версия %s; перед настройкой сервиса выполните install/update", version, remote.ToolVersion))
		}
		if commandErr != nil {
			r.Warnings = append(r.Warnings, "сервер вернул ненулевой код вместе с валидным отчётом; результаты сохранены")
		}
		return r
	}
	if commandErr != nil {
		message := "удалённая операция workload завершилась с ошибкой"
		if errors.Is(commandErr, context.DeadlineExceeded) {
			message = "превышен таймаут операции workload"
		}
		details := map[string]string{"hint": "обновите серверную часть и sudoers через «Установить/обновить»"}
		if value := strings.TrimSpace(string(stderr)); value != "" {
			details["stderr"] = limit(value, 4000)
		}
		r.Add(report.Result{Control: "remote-execution", Status: report.Fail, Severity: "critical", Message: message, Details: details})
		return r
	}
	r.Add(report.Result{Control: "remote-report", Status: report.Fail, Severity: "critical", Message: "сервер вернул некорректный JSON-отчёт", Details: map[string]string{"error": reportErr.Error()}})
	return r
}
