package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"bastionctl/internal/config"
	"bastionctl/internal/report"
	"bastionctl/internal/server"
	"bastionctl/internal/sshkey"
)

type CreateUserOptions struct {
	Connection Options
	Username   string
	PublicKey  string
	GrantSudo  bool
}

func CreateUser(ctx context.Context, cfg config.AdminConfig, version string, options CreateUserOptions) *report.Report {
	r := report.New(version, "admin", "user-add", options.Connection.Target)
	if err := validateConnection(options.Connection); err != nil {
		r.Add(report.Result{Control: "connection", Status: report.Fail, Severity: "critical", Message: err.Error()})
		return r
	}
	request, err := server.NewUserRequest(options.Username, options.PublicKey, options.GrantSudo)
	if err != nil {
		r.Add(report.Result{Control: "request", Status: report.Fail, Severity: "critical", Message: err.Error()})
		return r
	}
	payload, err := json.Marshal(request)
	if err != nil {
		r.Add(report.Result{Control: "request", Status: report.Fail, Severity: "critical", Message: err.Error()})
		return r
	}
	parts := []string{"sudo", "-n", cfg.RemoteExecutable, "server", "user-add", "--config", cfg.RemoteConfig, "--json", "--yes"}
	stdout, stderr, commandErr := runRawSSHInput(ctx, cfg, options.Connection, remoteCommand(parts), bytes.NewReader(append(payload, '\n')), 5*time.Minute)
	remote, reportErr := decodeRemoteReport(stdout, "user-add")
	if reportErr == nil {
		r.Results = append(r.Results, remote.Results...)
		r.Warnings = append(r.Warnings, remote.Warnings...)
		if remote.ToolVersion != version {
			r.Warnings = append(r.Warnings, fmt.Sprintf("локальная версия %s, серверная версия %s; перед созданием пользователей рекомендуется fleet install", version, remote.ToolVersion))
		}
		if commandErr != nil {
			r.Warnings = append(r.Warnings, "сервер вернул ненулевой код вместе с валидным отчётом; результаты сохранены")
		}
		return r
	}
	if commandErr != nil {
		message := "удалённое создание пользователя завершилось с ошибкой"
		if errors.Is(commandErr, context.DeadlineExceeded) {
			message = "превышен таймаут создания пользователя"
		}
		details := map[string]string{"hint": "обновите серверную часть через fleet install; sudoers версии 1.2.0 разрешает фиксированную команду user-add"}
		if value := strings.TrimSpace(string(stderr)); value != "" {
			details["stderr"] = limit(value, 4000)
		}
		r.Add(report.Result{Control: "remote-execution", Status: report.Fail, Severity: "critical", Message: message, Details: details})
		return r
	}
	r.Add(report.Result{Control: "remote-report", Status: report.Fail, Severity: "critical", Message: "сервер вернул некорректный JSON-отчёт", Details: map[string]string{"error": reportErr.Error()}})
	return r
}

func SetUserPassword(ctx context.Context, cfg config.AdminConfig, connection Options, username string, input io.Reader, output io.Writer) error {
	if err := sshkey.ValidateUsername(username); err != nil {
		return err
	}
	command := remoteCommand([]string{"sudo", "passwd", "--", username})
	_, stderr, err := runInteractiveSSH(ctx, cfg, connection, command, input, output, 10*time.Minute)
	if err != nil {
		message := strings.TrimSpace(string(stderr))
		if message == "" {
			message = err.Error()
		}
		return fmt.Errorf("задать sudo-пароль: %s", limit(message, 2000))
	}
	return nil
}
