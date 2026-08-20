package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"bastionctl/internal/config"
	"bastionctl/internal/report"
)

type Options struct {
	Action   string
	Target   string
	Port     int
	Identity string
	Yes      bool
}

var userPattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_.-]{0,31}$`)

func Doctor(ctx context.Context, cfg config.AdminConfig, version, identity string) *report.Report {
	r := report.New(version, "admin", "doctor", "local")
	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		r.Add(report.Result{Control: "ssh-client", Status: report.Fail, Severity: "critical", Message: "OpenSSH Client не найден в PATH"})
	} else {
		versionCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(versionCtx, sshPath, "-V")
		output, commandErr := cmd.CombinedOutput()
		status := report.Pass
		message := strings.TrimSpace(string(output))
		if commandErr != nil && message == "" {
			status = report.Warn
			message = commandErr.Error()
		}
		r.Add(report.Result{Control: "ssh-client", Status: status, Severity: "critical", Message: "OpenSSH Client доступен", Details: map[string]string{"path": sshPath, "version": message}})
	}
	for _, dependency := range []struct {
		name    string
		control string
	}{
		{name: "scp", control: "scp-client"},
		{name: "ssh-keygen", control: "ssh-keygen"},
	} {
		path, lookupErr := exec.LookPath(dependency.name)
		if lookupErr != nil {
			r.Add(report.Result{Control: dependency.control, Status: report.Fail, Severity: "critical", Message: dependency.name + " не найден в PATH"})
		} else {
			r.Add(report.Result{Control: dependency.control, Status: report.Pass, Severity: "high", Message: dependency.name + " доступен", Details: map[string]string{"path": path}})
		}
	}

	if identity == "" {
		r.Add(report.Result{Control: "identity", Status: report.Warn, Severity: "medium", Message: "ключ не указан; будет использован SSH agent или стандартный ключ"})
	} else if info, statErr := os.Lstat(identity); statErr != nil {
		r.Add(report.Result{Control: "identity", Status: report.Fail, Severity: "critical", Message: "файл закрытого ключа недоступен", Details: map[string]string{"error": statErr.Error()}})
	} else if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		r.Add(report.Result{Control: "identity", Status: report.Fail, Severity: "critical", Message: "путь ключа должен быть обычным файлом без symlink"})
	} else {
		status := report.Pass
		message := "файл ключа доступен"
		if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
			status = report.Warn
			message = "права ключа слишком широкие; рекомендуется chmod 600"
		}
		r.Add(report.Result{Control: "identity", Status: status, Severity: "high", Message: message, Details: map[string]string{"path": identity}})
	}

	if cfg.StrictHostKeyChecking {
		r.Add(report.Result{Control: "host-key-policy", Status: report.Pass, Severity: "critical", Message: "неизвестные и изменившиеся host keys отклоняются"})
	} else {
		r.Add(report.Result{Control: "host-key-policy", Status: report.Warn, Severity: "high", Message: "включён режим accept-new; fingerprint всё равно нужно сверить независимым каналом"})
	}
	return r
}

func Run(ctx context.Context, cfg config.AdminConfig, version string, options Options) *report.Report {
	r := report.New(version, "admin", options.Action, options.Target)
	if options.Action != "audit" && options.Action != "plan" && options.Action != "apply" && options.Action != "reset-plan" && options.Action != "reset" {
		r.Add(report.Result{Control: "arguments", Status: report.Fail, Severity: "critical", Message: "неизвестное удалённое действие"})
		return r
	}
	if err := ValidateTarget(options.Target); err != nil {
		r.Add(report.Result{Control: "target", Status: report.Fail, Severity: "critical", Message: err.Error()})
		return r
	}
	if options.Port < 1 || options.Port > 65535 {
		r.Add(report.Result{Control: "port", Status: report.Fail, Severity: "critical", Message: "SSH-порт должен быть в диапазоне 1..65535"})
		return r
	}
	if (options.Action == "apply" || options.Action == "reset") && !options.Yes {
		r.Add(report.Result{Control: "confirmation", Status: report.Fail, Severity: "critical", Message: "admin " + options.Action + " требует явный флаг --yes"})
		return r
	}
	remoteParts := []string{"sudo", "-n", cfg.RemoteExecutable, "server", options.Action, "--config", cfg.RemoteConfig, "--json"}
	if options.Action == "apply" || options.Action == "reset" {
		remoteParts = append(remoteParts, "--yes")
	}
	stdout, stderr, commandErr := runRawSSH(ctx, cfg, options, remoteCommand(remoteParts), 15*time.Minute)
	remote, reportErr := decodeRemoteReport(stdout, options.Action)
	if reportErr == nil {
		r.Results = append(r.Results, remote.Results...)
		r.Warnings = append(r.Warnings, remote.Warnings...)
		r.BackupDir = remote.BackupDir
		if remote.ToolVersion != version {
			r.Warnings = append(r.Warnings, fmt.Sprintf("локальная версия %s, серверная версия %s", version, remote.ToolVersion))
		}
		if commandErr != nil {
			r.Warnings = append(r.Warnings, "сервер вернул ненулевой код вместе с валидным отчётом; результаты сохранены")
		}
		return r
	}
	if commandErr != nil {
		message := "удалённая команда завершилась с ошибкой"
		if errors.Is(commandErr, context.DeadlineExceeded) {
			message = "превышен таймаут удалённой команды"
		}
		details := map[string]string{}
		if value := strings.TrimSpace(string(stderr)); value != "" {
			details["stderr"] = limit(value, 4000)
		}
		r.Add(report.Result{Control: "remote-execution", Status: report.Fail, Severity: "critical", Message: message, Details: details})
		return r
	}
	r.Add(report.Result{Control: "remote-report", Status: report.Fail, Severity: "critical", Message: "сервер вернул некорректный JSON-отчёт", Details: map[string]string{"error": reportErr.Error()}})
	return r
}

func decodeRemoteReport(data []byte, action string) (report.Report, error) {
	var remote report.Report
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&remote); err != nil {
		return report.Report{}, err
	}
	if remote.Schema != report.Schema {
		return report.Report{}, fmt.Errorf("неподдерживаемая схема %q", remote.Schema)
	}
	if remote.Mode != "server" || remote.Action != action {
		return report.Report{}, fmt.Errorf("ожидался server/%s, получен %s/%s", action, remote.Mode, remote.Action)
	}
	if remote.Results == nil {
		return report.Report{}, errors.New("отчёт не содержит results")
	}
	return remote, nil
}

func ValidateTarget(target string) error {
	separator := strings.LastIndex(target, "@")
	if separator <= 0 || separator == len(target)-1 || strings.Count(target, "@") != 1 {
		return errors.New("цель должна иметь вид user@host")
	}
	username, host := target[:separator], target[separator+1:]
	if !userPattern.MatchString(username) {
		return errors.New("недопустимое имя SSH-пользователя")
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	if net.ParseIP(host) != nil {
		return nil
	}
	if len(host) > 253 || strings.HasPrefix(host, "-") || strings.HasSuffix(host, "-") {
		return errors.New("недопустимое имя SSH-хоста")
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return errors.New("недопустимое имя SSH-хоста")
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') && char != '-' {
				return errors.New("недопустимое имя SSH-хоста")
			}
		}
	}
	return nil
}

func ExpandIdentity(path string) string {
	if path == "" || path[0] != '~' || (len(path) > 1 && path[1] != '/' && path[1] != '\\') {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	if len(path) == 1 {
		return home
	}
	return filepath.Join(home, path[2:])
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func limit(value string, maximum int) string {
	if len(value) <= maximum {
		return value
	}
	return value[:maximum] + "…"
}
