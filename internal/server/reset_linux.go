//go:build linux

package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"bastionctl/internal/config"
	"bastionctl/internal/report"
)

type resetFile struct {
	control  string
	path     string
	activate func(*serverContext) error
}

func resetPlatform(ctx context.Context, cfg config.Config, version string, options Options) *report.Report {
	r := report.New(version, "server", options.Action, "localhost")
	if options.Action != "reset-plan" && options.Action != "reset" {
		r.Add(report.Result{Control: "arguments", Status: report.Fail, Severity: "critical", Message: "неизвестное действие сброса"})
		return r
	}
	serverCtx := &serverContext{context: ctx, config: cfg, version: version, options: options, distro: readDistribution()}
	r.Add(report.Result{
		Control: "data-safety", Status: report.Pass, Severity: "critical",
		Message: "сброс ограничен файлами с маркером bastionctl и помеченными правилами UFW",
		Details: map[string]string{"preserved": "/home, /root, /srv, /var/lib, пользовательские аккаунты, authorized_keys, пакеты и сторонние правила firewall"},
	})
	if options.Action == "reset-plan" {
		for _, item := range resetFiles() {
			r.Add(planResetFile(item))
		}
		r.Add(planResetFirewall(ctx))
		r.Warnings = append(r.Warnings,
			"сброс удаляет только политику, однозначно принадлежащую bastionctl; сторонняя конфигурация и пользовательские данные не изменяются",
			"пакеты и общие systemd-сервисы не удаляются и не отключаются, потому что они могли использоваться до bastionctl",
			"после удаления sysctl drop-in рекомендуется плановая перезагрузка: параметры без другого источника окончательно вернутся к загрузочным значениям после reboot",
		)
		return r
	}
	if !options.Yes {
		r.Add(report.Result{Control: "confirmation", Status: report.Fail, Severity: "critical", Message: "server reset требует --yes после отдельного reset-plan"})
		return r
	}
	if os.Geteuid() != 0 {
		r.Add(report.Result{Control: "privileges", Status: report.Fail, Severity: "critical", Message: "server reset должен выполняться от root"})
		return r
	}
	lock, err := acquireLock()
	if err != nil {
		r.Add(report.Result{Control: "process-lock", Status: report.Fail, Severity: "critical", Message: err.Error()})
		return r
	}
	defer lock.Close()
	backupRoot, err := newBackupRoot()
	if err != nil {
		r.Add(failResult("backup", "не удалось создать резервную копию перед сбросом", err))
		return r
	}
	serverCtx.backupRoot = backupRoot
	r.BackupDir = backupRoot
	for _, item := range resetFiles() {
		result := applyResetFile(serverCtx, item)
		r.Add(result)
		if result.Status == report.Fail {
			r.Add(report.Result{Control: "reset", Status: report.Fail, Severity: "critical", Message: "сброс остановлен после ошибки; уже выполненные безопасные удаления перечислены в отчёте"})
			return r
		}
	}
	r.Add(applyResetFirewall(serverCtx))
	r.Warnings = append(r.Warnings,
		"учётные записи и SSH-ключи намеренно сохранены, чтобы не заблокировать доступ и не удалить пользовательские данные",
		"пакеты, общие сервисы, UFW enable/default policy и непомеченные правила сохранены",
		"выполните плановую перезагрузку, если нужно немедленно убрать runtime sysctl, для которого нет другого системного значения",
	)
	return r
}

func resetFiles() []resetFile {
	return []resetFile{
		{control: "automatic-updates", path: "/etc/apt/apt.conf.d/52bastionctl-unattended-upgrades"},
		{control: "sysctl", path: "/etc/sysctl.d/99-bastionctl.conf", activate: func(ctx *serverContext) error {
			result := runCommand(ctx.context, "", "sysctl", "--system")
			if result.Err != nil {
				return errors.New(firstError(result))
			}
			return nil
		}},
		{control: "journald", path: "/etc/systemd/journald.conf.d/60-bastionctl.conf", activate: tryRestart("systemd-journald.service")},
		{control: "auditd", path: "/etc/audit/rules.d/60-bastionctl.rules", activate: func(ctx *serverContext) error {
			if _, err := findCommand("augenrules"); err != nil {
				return nil
			}
			result := runCommand(ctx.context, "", "augenrules", "--load")
			if result.Err != nil {
				return errors.New(firstError(result))
			}
			return nil
		}},
		{control: "fail2ban", path: "/etc/fail2ban/jail.d/sshd-bastionctl.local", activate: tryRestart("fail2ban.service")},
		{control: "ssh", path: "/etc/ssh/sshd_config.d/00-bastionctl.conf", activate: func(ctx *serverContext) error {
			test := runCommand(ctx.context, "", "sshd", "-t")
			if test.Err != nil {
				return fmt.Errorf("sshd -t: %s", firstError(test))
			}
			return reloadSSH(ctx)
		}},
	}
}

func tryRestart(unit string) func(*serverContext) error {
	return func(ctx *serverContext) error {
		if _, err := findCommand("systemctl"); err != nil {
			return nil
		}
		result := runCommand(ctx.context, "", "systemctl", "try-restart", unit)
		if result.Err != nil {
			return errors.New(firstError(result))
		}
		return nil
	}
}

func planResetFile(item resetFile) report.Result {
	managed, exists, err := inspectResetFile(item.path)
	if err != nil {
		return failResult(item.control, "не удалось проверить управляемый файл", err)
	}
	if !exists {
		return report.Result{Control: item.control, Status: report.Skipped, Severity: "low", Message: "управляемый файл отсутствует", Details: map[string]string{"path": item.path}}
	}
	if !managed {
		return report.Result{Control: item.control, Status: report.Warn, Severity: "critical", Message: "файл не содержит маркер bastionctl и будет сохранён", Details: map[string]string{"path": item.path}}
	}
	return report.Result{Control: item.control, Status: report.Planned, Severity: "high", Message: "удалить файл bastionctl, проверить конфигурацию и активировать оставшиеся настройки", Details: map[string]string{"path": item.path}}
}

func applyResetFile(ctx *serverContext, item resetFile) report.Result {
	managed, exists, err := inspectResetFile(item.path)
	if err != nil {
		return failResult(item.control, "не удалось проверить управляемый файл", err)
	}
	if !exists {
		return report.Result{Control: item.control, Status: report.Pass, Severity: "low", Message: "управляемый файл уже отсутствует", Details: map[string]string{"path": item.path}}
	}
	if !managed {
		return report.Result{Control: item.control, Status: report.Warn, Severity: "critical", Message: "файл без маркера bastionctl сохранён", Details: map[string]string{"path": item.path}}
	}
	snapshot, err := snapshotFile(item.path, ctx.backupRoot, "reset-"+item.control)
	if err != nil {
		return failResult(item.control, "не удалось сохранить файл перед сбросом", err)
	}
	if err := os.Remove(item.path); err != nil {
		return failResult(item.control, "не удалось удалить управляемый файл", err)
	}
	if err := syncDirectory(filepath.Dir(item.path)); err != nil {
		_ = snapshot.Restore()
		return failResult(item.control, "не удалось синхронизировать удаление", err)
	}
	if item.activate != nil {
		if err := item.activate(ctx); err != nil {
			restoreErr := snapshot.Restore()
			if restoreErr == nil {
				_ = item.activate(ctx)
			}
			return rollbackFailure(item.control, "оставшаяся системная конфигурация не прошла проверку", err, restoreErr)
		}
	}
	return report.Result{Control: item.control, Status: report.Changed, Severity: "high", Message: "управляемый файл удалён; оставшаяся конфигурация активирована", Changed: true, Details: map[string]string{"path": item.path}}
}

func inspectResetFile(path string) (managed, exists bool, resultErr error) {
	if err := rejectSymlinkParents(filepath.Dir(path)); err != nil {
		return false, false, err
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return false, true, errors.New("целевой путь должен быть обычным файлом без symlink размером не более 1 MiB")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false, true, err
	}
	firstLine := strings.TrimSpace(strings.SplitN(string(data), "\n", 2)[0])
	managed = strings.HasPrefix(firstLine, "# Managed by bastionctl.") || strings.HasPrefix(firstLine, "// Managed by bastionctl.")
	return managed, true, nil
}

var ufwNumberPattern = regexp.MustCompile(`^\s*\[\s*([0-9]+)\]`)
var ufwTagPattern = regexp.MustCompile(`#\s*bastionctl-(ssh|service)\s*$`)

func taggedUFWRules(output string) []int {
	return taggedUFWRulesByKind(output, "")
}

func taggedUFWRulesByKind(output, expectedKind string) []int {
	values := make([]int, 0)
	seen := map[int]struct{}{}
	for _, line := range strings.Split(output, "\n") {
		tag := ufwTagPattern.FindStringSubmatch(line)
		if len(tag) != 2 || (expectedKind != "" && tag[1] != expectedKind) {
			continue
		}
		match := ufwNumberPattern.FindStringSubmatch(line)
		if len(match) != 2 {
			continue
		}
		value, err := strconv.Atoi(match[1])
		if err == nil && value > 0 {
			seen[value] = struct{}{}
		}
	}
	for value := range seen {
		values = append(values, value)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(values)))
	return values
}

func planResetFirewall(ctx context.Context) report.Result {
	if _, err := findCommand("ufw"); err != nil {
		return report.Result{Control: "firewall", Status: report.Skipped, Severity: "low", Message: "UFW не установлен; правил bastionctl нет"}
	}
	status := runCommand(ctx, "", "ufw", "status", "numbered")
	if status.Err != nil {
		return commandFailure("firewall", "не удалось проверить правила UFW", status)
	}
	rules, preservedSSH, protectionWarning := resettableUFWRules(ctx, status.Stdout)
	if len(rules) == 0 {
		if len(preservedSSH) > 0 {
			return report.Result{Control: "firewall", Status: report.Warn, Severity: "critical", Message: "SSH-правила bastionctl будут сохранены, чтобы reset не заблокировал повторный вход", Details: map[string]string{"preserved_ssh_rule_numbers": joinInts(preservedSSH), "reason": protectionWarning}}
		}
		return report.Result{Control: "firewall", Status: report.Skipped, Severity: "low", Message: "помеченные правила bastionctl отсутствуют; UFW policy и сторонние правила сохранятся"}
	}
	details := map[string]string{"rule_numbers": joinInts(rules), "preserved": "UFW enable state, default policy и все непомеченные правила"}
	if len(preservedSSH) > 0 {
		details["preserved_ssh_rule_numbers"] = joinInts(preservedSSH)
		details["ssh_safety"] = protectionWarning
	}
	return report.Result{Control: "firewall", Status: report.Planned, Severity: "critical", Message: "удалить только безопасно удаляемые правила bastionctl; необходимый SSH allow сохранить", Details: details}
}

func applyResetFirewall(ctx *serverContext) report.Result {
	if _, err := findCommand("ufw"); err != nil {
		return report.Result{Control: "firewall", Status: report.Pass, Severity: "low", Message: "UFW не установлен; изменений нет"}
	}
	status := runCommand(ctx.context, "", "ufw", "status", "numbered")
	if status.Err != nil {
		return commandFailure("firewall", "не удалось проверить правила UFW", status)
	}
	rules, preservedSSH, protectionWarning := resettableUFWRules(ctx.context, status.Stdout)
	if len(rules) == 0 {
		if len(preservedSSH) > 0 {
			return report.Result{Control: "firewall", Status: report.Warn, Severity: "critical", Message: "SSH-правила bastionctl сохранены, чтобы не заблокировать повторный вход", Details: map[string]string{"preserved_ssh_rule_numbers": joinInts(preservedSSH), "reason": protectionWarning}}
		}
		return report.Result{Control: "firewall", Status: report.Pass, Severity: "high", Message: "помеченные правила bastionctl уже отсутствуют; остальные правила сохранены"}
	}
	statusPath := filepath.Join(ctx.backupRoot, "reset-firewall", "ufw-status-numbered.txt")
	if err := os.MkdirAll(filepath.Dir(statusPath), 0o700); err != nil {
		return failResult("firewall", "не удалось создать журнал правил перед сбросом", err)
	}
	if err := atomicWrite(statusPath, []byte(status.Stdout+"\n"), 0o600, 0, 0); err != nil {
		return failResult("firewall", "не удалось сохранить список правил перед сбросом", err)
	}
	deleted := make([]int, 0, len(rules))
	for _, number := range rules {
		result := runCommand(ctx.context, "", "ufw", "--force", "delete", strconv.Itoa(number))
		if result.Err != nil {
			return report.Result{Control: "firewall", Status: report.Fail, Severity: "critical", Message: "удаление помеченных правил UFW остановлено; сторонние правила не изменялись", Details: map[string]string{"deleted": joinInts(deleted), "failed_rule": strconv.Itoa(number), "error": firstError(result), "backup": statusPath}}
		}
		deleted = append(deleted, number)
	}
	details := map[string]string{"deleted_rule_numbers": joinInts(deleted), "backup": statusPath}
	if len(preservedSSH) > 0 {
		details["preserved_ssh_rule_numbers"] = joinInts(preservedSSH)
		details["ssh_safety"] = protectionWarning
	}
	return report.Result{Control: "firewall", Status: report.Changed, Severity: "critical", Message: "безопасно удаляемые правила bastionctl удалены; необходимый SSH allow, UFW и сторонние правила сохранены", Changed: true, Details: details}
}

func resettableUFWRules(ctx context.Context, numberedOutput string) (deletable, preservedSSH []int, warning string) {
	all := taggedUFWRules(numberedOutput)
	if len(all) == 0 {
		return nil, nil, ""
	}
	sshRules := taggedUFWRulesByKind(numberedOutput, "ssh")
	serviceRules := taggedUFWRulesByKind(numberedOutput, "service")
	verbose := runCommand(ctx, "", "ufw", "status", "verbose")
	if verbose.Err != nil {
		return serviceRules, sshRules, "статус UFW policy не прочитан; SSH allow сохранён консервативно"
	}
	lower := strings.ToLower(verbose.Stdout)
	denyIncoming := strings.Contains(lower, "default: deny (incoming)") || strings.Contains(lower, "default: reject (incoming)")
	allowIncoming := strings.Contains(lower, "default: allow (incoming)")
	if !allowIncoming && len(sshRules) > 0 {
		reason := "безопасная default allow incoming не подтверждена; SSH allow сохранён консервативно"
		if denyIncoming {
			reason = "UFW использует deny/reject incoming; удаление SSH allow может закрыть доступ"
		}
		return serviceRules, sshRules, reason
	}
	return all, nil, ""
}
