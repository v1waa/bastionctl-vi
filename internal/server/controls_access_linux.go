//go:build linux

package server

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"bastionctl/internal/report"
)

type permissionRule struct {
	path string
	mode os.FileMode
	uid  int
	gid  int
}

func permissionsControl() control {
	return functionalControl{
		name:    "permissions",
		enabled: func(ctx *serverContext) bool { return ctx.config.Server.ManagePermissions },
		audit: func(ctx *serverContext) []report.Result {
			rules, err := permissionRules(ctx)
			if err != nil {
				return []report.Result{failResult("permissions", "не удалось построить правила прав", err)}
			}
			results := make([]report.Result, 0, len(rules))
			for _, rule := range rules {
				results = append(results, auditPermission(rule))
			}
			return results
		},
		plan: func(ctx *serverContext) report.Result {
			rules, _ := permissionRules(ctx)
			paths := make([]string, 0, len(rules))
			for _, rule := range rules {
				paths = append(paths, fmt.Sprintf("%s:%04o", rule.path, rule.mode))
			}
			return report.Result{Control: "permissions", Status: report.Planned, Severity: "high", Message: "исправить только владельца и права чувствительных файлов", Details: map[string]string{"rules": strings.Join(paths, ", ")}}
		},
		preflight: func(ctx *serverContext) []report.Result {
			rules, err := permissionRules(ctx)
			if err != nil {
				return []report.Result{{Status: report.Fail, Severity: "critical", Message: err.Error()}}
			}
			for _, rule := range rules {
				info, statErr := os.Lstat(rule.path)
				if statErr != nil {
					if os.IsNotExist(statErr) && rule.path != ctx.options.ConfigPath {
						continue
					}
					return []report.Result{{Status: report.Fail, Severity: "critical", Message: "чувствительный файл недоступен", Details: map[string]string{"path": rule.path, "error": statErr.Error()}}}
				}
				if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
					return []report.Result{{Status: report.Fail, Severity: "critical", Message: "чувствительный путь должен быть обычным файлом без symlink", Details: map[string]string{"path": rule.path}}}
				}
			}
			return []report.Result{{Status: report.Pass, Severity: "high", Message: "чувствительные пути безопасны для изменения метаданных"}}
		},
		apply: func(ctx *serverContext) report.Result {
			rules, err := permissionRules(ctx)
			if err != nil {
				return failResult("permissions", "не удалось построить правила прав", err)
			}
			changed := make([]string, 0)
			for _, rule := range rules {
				info, statErr := os.Stat(rule.path)
				if os.IsNotExist(statErr) && rule.path != ctx.options.ConfigPath {
					continue
				}
				if statErr != nil {
					return failResult("permissions", "не удалось прочитать метаданные "+rule.path, statErr)
				}
				stat, ok := info.Sys().(*syscall.Stat_t)
				if !ok {
					return failResult("permissions", "не удалось определить владельца "+rule.path, nil)
				}
				if info.Mode().Perm() == rule.mode && int(stat.Uid) == rule.uid && int(stat.Gid) == rule.gid {
					continue
				}
				if err := os.Chown(rule.path, rule.uid, rule.gid); err != nil {
					return failResult("permissions", "не удалось изменить владельца "+rule.path, err)
				}
				if err := os.Chmod(rule.path, rule.mode); err != nil {
					return failResult("permissions", "не удалось изменить права "+rule.path, err)
				}
				changed = append(changed, rule.path)
			}
			if len(changed) == 0 {
				return report.Result{Control: "permissions", Status: report.Pass, Severity: "high", Message: "права чувствительных файлов уже корректны"}
			}
			return report.Result{Control: "permissions", Status: report.Changed, Severity: "high", Message: "права чувствительных файлов исправлены", Changed: true, Details: map[string]string{"paths": strings.Join(changed, ", ")}}
		},
	}
}

func permissionRules(ctx *serverContext) ([]permissionRule, error) {
	shadowGID := 0
	if group, err := user.LookupGroup("shadow"); err == nil {
		parsed, parseErr := strconv.Atoi(group.Gid)
		if parseErr != nil {
			return nil, parseErr
		}
		shadowGID = parsed
	}
	rules := []permissionRule{
		{path: "/etc/shadow", mode: 0o640, uid: 0, gid: shadowGID},
		{path: "/etc/gshadow", mode: 0o640, uid: 0, gid: shadowGID},
		{path: "/etc/ssh/sshd_config", mode: 0o600, uid: 0, gid: 0},
		{path: "/etc/sudoers", mode: 0o440, uid: 0, gid: 0},
		{path: ctx.options.ConfigPath, mode: 0o600, uid: 0, gid: 0},
	}
	return rules, nil
}

func auditPermission(rule permissionRule) report.Result {
	info, err := os.Stat(rule.path)
	if err != nil {
		return failResult("permissions", "файл недоступен: "+rule.path, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return failResult("permissions", "владелец файла не определён: "+rule.path, nil)
	}
	details := map[string]string{"path": rule.path, "actual_mode": fmt.Sprintf("%04o", info.Mode().Perm()), "expected_mode": fmt.Sprintf("%04o", rule.mode)}
	if info.Mode().Perm() != rule.mode || int(stat.Uid) != rule.uid || int(stat.Gid) != rule.gid {
		return report.Result{Control: "permissions", Status: report.Fail, Severity: "high", Message: "владелец или права файла не соответствуют политике", Details: details}
	}
	return report.Result{Control: "permissions", Status: report.Pass, Severity: "high", Message: "права файла корректны", Details: details}
}

func sshControl() control {
	const path = "/etc/ssh/sshd_config.d/00-bastionctl.conf"
	return functionalControl{
		name:    "ssh",
		enabled: func(ctx *serverContext) bool { return ctx.config.Server.ManageSSH },
		audit: func(ctx *serverContext) []report.Result {
			values, ports, err := effectiveSSH(ctx)
			if err != nil {
				return []report.Result{failResult("ssh", "не удалось получить эффективную конфигурацию sshd", err)}
			}
			ctx.sshPorts = ports
			expected := expectedSSHValues(ctx)
			mismatches := make([]string, 0)
			for key, wanted := range expected {
				if values[key] != wanted {
					mismatches = append(mismatches, key+"="+values[key]+" (ожидается "+wanted+")")
				}
			}
			sort.Strings(mismatches)
			if len(mismatches) > 0 {
				return []report.Result{{Control: "ssh", Status: report.Fail, Severity: "critical", Message: "эффективная конфигурация SSH не соответствует политике", Details: map[string]string{"mismatches": strings.Join(mismatches, "; "), "ports": joinInts(ports)}}}
			}
			return []report.Result{{Control: "ssh", Status: report.Pass, Severity: "critical", Message: "эффективная конфигурация SSH соответствует политике", Details: map[string]string{"ports": joinInts(ports)}}}
		},
		plan: func(_ *serverContext) report.Result {
			return report.Result{Control: "ssh", Status: report.Planned, Severity: "critical", Message: "проверить ключ и sudo администратора, записать drop-in, выполнить sshd -t/-T и reload с откатом при ошибке", Details: map[string]string{"path": path}}
		},
		preflight: func(ctx *serverContext) []report.Result {
			return sshPreflight(ctx, path)
		},
		apply: func(ctx *serverContext) report.Result {
			content := desiredSSHConfig(ctx)
			current, err := os.ReadFile(path)
			if err == nil && string(current) == content {
				if verifyErr := verifyEffectiveSSH(ctx); verifyErr != nil {
					return failResult("ssh", "drop-in существует, но эффективная политика не совпадает", verifyErr)
				}
				return report.Result{Control: "ssh", Status: report.Pass, Severity: "critical", Message: "SSH уже соответствует политике"}
			}
			snapshot, err := snapshotFile(path, ctx.backupRoot, "ssh")
			if err != nil {
				return failResult("ssh", "не удалось создать резервную копию SSH drop-in", err)
			}
			if err := snapshot.Write([]byte(content), 0o600); err != nil {
				return failResult("ssh", "не удалось записать SSH drop-in", err)
			}
			if test := runCommand(ctx.context, "", "sshd", "-t"); test.Err != nil {
				restoreErr := snapshot.Restore()
				return rollbackFailure("ssh", "sshd -t отклонил конфигурацию", fmt.Errorf("%s", firstError(test)), restoreErr)
			}
			if err := verifyEffectiveSSH(ctx); err != nil {
				restoreErr := snapshot.Restore()
				return rollbackFailure("ssh", "sshd -T показал неэффективную политику", err, restoreErr)
			}
			if err := reloadSSH(ctx); err != nil {
				restoreErr := snapshot.Restore()
				if restoreErr == nil {
					_ = reloadSSH(ctx)
				}
				return rollbackFailure("ssh", "не удалось перезагрузить SSH", err, restoreErr)
			}
			return report.Result{Control: "ssh", Status: report.Changed, Severity: "critical", Message: "SSH-политика проверена и применена", Changed: true, Details: map[string]string{"path": path, "ports": joinInts(ctx.sshPorts)}}
		},
	}
}

func sshPreflight(ctx *serverContext, path string) []report.Result {
	results := make([]report.Result, 0)
	for _, command := range []string{"sshd", "ssh-keygen", "systemctl"} {
		if _, err := findCommand(command); err != nil {
			results = append(results, report.Result{Status: report.Fail, Severity: "critical", Message: err.Error()})
			return results
		}
	}
	if err := preflightManagedPath(path); err != nil {
		results = append(results, report.Result{Status: report.Fail, Severity: "critical", Message: err.Error(), Details: map[string]string{"path": path}})
		return results
	}
	if test := runCommand(ctx.context, "", "sshd", "-t"); test.Err != nil {
		results = append(results, report.Result{Status: report.Fail, Severity: "critical", Message: "текущая конфигурация sshd уже некорректна", Details: map[string]string{"error": firstError(test)}})
		return results
	}
	adminUser, err := resolveAdminUser(ctx)
	if err != nil {
		results = append(results, report.Result{Status: report.Fail, Severity: "critical", Message: err.Error()})
		return results
	}
	keyPath, err := findUsableAuthorizedKeys(ctx, adminUser)
	if err != nil {
		results = append(results, report.Result{Status: report.Fail, Severity: "critical", Message: err.Error()})
		return results
	}
	ctx.adminUser = adminUser.Username
	if !userCanAdmin(ctx, adminUser) {
		results = append(results, report.Result{Status: report.Fail, Severity: "critical", Message: "администратор не состоит в группе sudo или wheel", Details: map[string]string{"user": adminUser.Username}})
		return results
	}
	_, ports, err := effectiveSSH(ctx)
	if err != nil || len(ports) == 0 {
		if err == nil {
			err = fmt.Errorf("sshd не сообщил ни одного порта")
		}
		results = append(results, report.Result{Status: report.Fail, Severity: "critical", Message: "не удалось определить SSH-порт", Details: map[string]string{"error": err.Error()}})
		return results
	}
	ctx.sshPorts = ports
	results = append(results, report.Result{Status: report.Pass, Severity: "critical", Message: "SSH preflight пройден: ключ, sudo и текущая конфигурация проверены", Details: map[string]string{"admin_user": adminUser.Username, "authorized_keys": keyPath, "ports": joinInts(ports)}})
	return results
}

func resolveAdminUser(ctx *serverContext) (*user.User, error) {
	username := ctx.config.Server.AdminUser
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" && sudoUser != "root" {
		if username == "" {
			username = sudoUser
		}
	}
	if username == "" || username == "root" {
		return nil, fmt.Errorf("server.admin_user должен указывать существующего непривилегированного администратора")
	}
	account, err := user.Lookup(username)
	if err != nil {
		return nil, fmt.Errorf("пользователь %s не найден: %w", username, err)
	}
	if account.Uid == "0" {
		return nil, fmt.Errorf("admin_user не может иметь UID 0")
	}
	return account, nil
}

func findUsableAuthorizedKeys(ctx *serverContext, account *user.User) (string, error) {
	result := runCommand(ctx.context, "", "sshd", "-T", "-C", "user="+account.Username+",host=localhost,addr=127.0.0.1")
	if result.Err != nil {
		return "", fmt.Errorf("sshd -T для пользователя: %s", firstError(result))
	}
	patterns := []string{".ssh/authorized_keys", ".ssh/authorized_keys2"}
	for _, line := range strings.Split(result.Stdout, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 1 && fields[0] == "authorizedkeysfile" {
			patterns = fields[1:]
			break
		}
	}
	uid, _ := strconv.Atoi(account.Uid)
	for _, pattern := range patterns {
		if pattern == "none" {
			continue
		}
		path := strings.ReplaceAll(pattern, "%h", account.HomeDir)
		path = strings.ReplaceAll(path, "%u", account.Username)
		path = strings.ReplaceAll(path, "%U", account.Uid)
		path = strings.ReplaceAll(path, "%%", "%")
		if !filepath.IsAbs(path) {
			path = filepath.Join(account.HomeDir, path)
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
			continue
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (int(stat.Uid) != uid && stat.Uid != 0) {
			continue
		}
		keyCheck := runCommand(ctx.context, "", "ssh-keygen", "-l", "-f", path)
		if keyCheck.Err == nil && strings.TrimSpace(keyCheck.Stdout) != "" {
			if err := checkSSHDirectories(account, uid); err != nil {
				return "", err
			}
			return path, nil
		}
	}
	return "", fmt.Errorf("для %s не найден безопасный authorized_keys с распознаваемым публичным ключом", account.Username)
}

func checkSSHDirectories(account *user.User, uid int) error {
	for _, path := range []string{account.HomeDir, filepath.Join(account.HomeDir, ".ssh")} {
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("каталог %s недоступен: %w", path, err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (int(stat.Uid) != uid && stat.Uid != 0) || info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("каталог %s имеет небезопасного владельца или права", path)
		}
	}
	return nil
}

func userCanAdmin(ctx *serverContext, account *user.User) bool {
	if _, err := findCommand("sudo"); err == nil {
		result := runCommand(ctx.context, "", "sudo", "-n", "-l", "-U", account.Username)
		if result.Err == nil && !strings.Contains(strings.ToLower(result.Stdout+result.Stderr), "not allowed") {
			return true
		}
	}
	groupIDs, err := account.GroupIds()
	if err != nil {
		return false
	}
	for _, id := range groupIDs {
		group, lookupErr := user.LookupGroupId(id)
		if lookupErr == nil && (group.Name == "sudo" || group.Name == "wheel") {
			return true
		}
	}
	return false
}

func desiredSSHConfig(ctx *serverContext) string {
	s := ctx.config.Server
	return fmt.Sprintf("# Managed by bastionctl. Local edits will be replaced.\nPermitRootLogin no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nAuthenticationMethods publickey\nPubkeyAuthentication yes\nMaxAuthTries %d\nLoginGraceTime %d\nClientAliveInterval %d\nClientAliveCountMax %d\nAllowTcpForwarding %s\nAllowStreamLocalForwarding %s\nAllowAgentForwarding %s\nX11Forwarding %s\nPermitTunnel no\nPermitUserEnvironment no\nLogLevel VERBOSE\n", s.MaxAuthTries, s.LoginGraceTime, s.ClientAliveInterval, s.ClientAliveCountMax, boolWord(s.AllowTCPForwarding), boolWord(s.AllowStreamLocalForwarding), boolWord(s.AllowAgentForwarding), boolWord(s.X11Forwarding))
}

func expectedSSHValues(ctx *serverContext) map[string]string {
	s := ctx.config.Server
	return map[string]string{
		"permitrootlogin": "no", "passwordauthentication": "no", "kbdinteractiveauthentication": "no",
		"authenticationmethods": "publickey", "pubkeyauthentication": "yes",
		"maxauthtries": strconv.Itoa(s.MaxAuthTries), "logingracetime": strconv.Itoa(s.LoginGraceTime),
		"clientaliveinterval": strconv.Itoa(s.ClientAliveInterval), "clientalivecountmax": strconv.Itoa(s.ClientAliveCountMax),
		"allowtcpforwarding": boolWord(s.AllowTCPForwarding), "allowstreamlocalforwarding": boolWord(s.AllowStreamLocalForwarding),
		"allowagentforwarding": boolWord(s.AllowAgentForwarding), "x11forwarding": boolWord(s.X11Forwarding),
		"permittunnel": "no", "permituserenvironment": "no", "loglevel": "VERBOSE",
	}
}

func effectiveSSH(ctx *serverContext) (map[string]string, []int, error) {
	args := []string{"-T"}
	username := ctx.adminUser
	if username == "" {
		username = ctx.config.Server.AdminUser
	}
	if username != "" {
		args = append(args, "-C", "user="+username+",host=localhost,addr=127.0.0.1")
	}
	result := runCommand(ctx.context, "", "sshd", args...)
	if result.Err != nil {
		return nil, nil, fmt.Errorf("%s", firstError(result))
	}
	values := map[string]string{}
	ports := make([]int, 0)
	for _, line := range strings.Split(result.Stdout, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if _, exists := values[fields[0]]; !exists {
			values[fields[0]] = strings.Join(fields[1:], " ")
		}
		if fields[0] == "port" {
			if port, err := strconv.Atoi(fields[1]); err == nil {
				ports = append(ports, port)
			}
		}
	}
	ports = sortedUnique(ports)
	return values, ports, nil
}

func verifyEffectiveSSH(ctx *serverContext) error {
	values, ports, err := effectiveSSH(ctx)
	if err != nil {
		return err
	}
	ctx.sshPorts = ports
	mismatches := make([]string, 0)
	for key, wanted := range expectedSSHValues(ctx) {
		if values[key] != wanted {
			mismatches = append(mismatches, fmt.Sprintf("%s=%q, ожидается %q", key, values[key], wanted))
		}
	}
	sort.Strings(mismatches)
	if len(mismatches) > 0 {
		return fmt.Errorf("%s", strings.Join(mismatches, "; "))
	}
	return nil
}

func reloadSSH(ctx *serverContext) error {
	var messages []string
	for _, unit := range []string{"ssh.service", "sshd.service"} {
		result := runCommand(ctx.context, "", "systemctl", "reload", unit)
		if result.Err == nil {
			return nil
		}
		messages = append(messages, unit+": "+firstError(result))
	}
	return fmt.Errorf("%s", strings.Join(messages, "; "))
}

func fail2banControl() control {
	const path = "/etc/fail2ban/jail.d/sshd-bastionctl.local"
	desired := func(ctx *serverContext) string {
		ports := ctx.sshPorts
		if len(ports) == 0 {
			_, discovered, err := effectiveSSH(ctx)
			if err == nil {
				ports = discovered
			}
		}
		if len(ports) == 0 {
			ports = []int{22}
		}
		s := ctx.config.Server
		return fmt.Sprintf("# Managed by bastionctl.\n[sshd]\nenabled = true\nbackend = systemd\nport = %s\nmaxretry = %d\nfindtime = %s\nbantime = %s\n", joinInts(ports), s.Fail2banMaxRetry, s.Fail2banFindTime, s.Fail2banBanTime)
	}
	base := managedTextControl(
		"fail2ban",
		func(ctx *serverContext) bool { return ctx.config.Server.ManageFail2ban },
		path,
		desired,
		0o640,
		"настроить jail sshd на всех эффективных SSH-портах",
		func(ctx *serverContext) error {
			result := runCommand(ctx.context, "", "fail2ban-client", "-t")
			if result.Err != nil {
				return fmt.Errorf("fail2ban-client -t: %s", firstError(result))
			}
			return nil
		},
		func(ctx *serverContext) error {
			result := runCommand(ctx.context, "", "systemctl", "enable", "--now", "fail2ban.service")
			if result.Err != nil {
				return fmt.Errorf("systemctl: %s", firstError(result))
			}
			restart := runCommand(ctx.context, "", "systemctl", "restart", "fail2ban.service")
			if restart.Err != nil {
				return fmt.Errorf("systemctl restart: %s", firstError(restart))
			}
			return nil
		},
	)
	return functionalControl{
		name:    "fail2ban",
		enabled: func(ctx *serverContext) bool { return ctx.config.Server.ManageFail2ban },
		audit: func(ctx *serverContext) []report.Result {
			results := base.Audit(ctx)
			active := runCommand(ctx.context, "", "systemctl", "is-active", "fail2ban.service")
			if active.Err != nil {
				results = append(results, report.Result{Control: "fail2ban", Status: report.Fail, Severity: "high", Message: "fail2ban не активен", Details: map[string]string{"state": firstError(active)}})
			} else {
				results = append(results, report.Result{Control: "fail2ban", Status: report.Pass, Severity: "high", Message: "fail2ban активен"})
			}
			return results
		},
		plan: base.Plan,
		preflight: func(ctx *serverContext) []report.Result {
			results := base.Preflight(ctx)
			_, ports, err := effectiveSSH(ctx)
			if err != nil || len(ports) == 0 {
				if err == nil {
					err = fmt.Errorf("порты отсутствуют")
				}
				return append(results, report.Result{Status: report.Fail, Severity: "critical", Message: "не удалось определить SSH-порты для fail2ban", Details: map[string]string{"error": err.Error()}})
			}
			ctx.sshPorts = ports
			return results
		},
		apply: base.Apply,
	}
}
