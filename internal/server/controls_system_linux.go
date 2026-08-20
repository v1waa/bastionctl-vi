//go:build linux

package server

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"bastionctl/internal/report"
)

func packagesControl() control {
	return functionalControl{
		name: "packages",
		audit: func(ctx *serverContext) []report.Result {
			packages := requiredPackages(ctx)
			missing := missingPackages(ctx, packages)
			if len(missing) == 0 {
				return []report.Result{{Control: "packages", Status: report.Pass, Severity: "high", Message: "все пакеты базового профиля установлены", Details: map[string]string{"packages": strings.Join(packages, ", ")}}}
			}
			return []report.Result{{Control: "packages", Status: report.Fail, Severity: "high", Message: "отсутствуют пакеты базового профиля", Details: map[string]string{"missing": strings.Join(missing, ", ")}}}
		},
		plan: func(ctx *serverContext) report.Result {
			return report.Result{Control: "packages", Status: report.Planned, Severity: "high", Message: "установить отсутствующие пакеты через apt без удаления существующих", Details: map[string]string{"packages": strings.Join(requiredPackages(ctx), ", ")}}
		},
		preflight: func(_ *serverContext) []report.Result {
			for _, command := range []string{"apt-get", "dpkg-query", "systemctl"} {
				if _, err := findCommand(command); err != nil {
					return []report.Result{{Status: report.Fail, Severity: "critical", Message: err.Error()}}
				}
			}
			return []report.Result{{Status: report.Pass, Severity: "critical", Message: "apt, dpkg-query и systemctl доступны"}}
		},
		apply: func(ctx *serverContext) report.Result {
			missing := missingPackages(ctx, requiredPackages(ctx))
			if len(missing) == 0 {
				return report.Result{Control: "packages", Status: report.Pass, Severity: "high", Message: "нужные пакеты уже установлены"}
			}
			update := runCommand(ctx.context, "", "apt-get", "update")
			if update.Err != nil {
				return commandFailure("packages", "apt-get update завершился с ошибкой", update)
			}
			args := append([]string{"install", "--yes", "--no-install-recommends"}, missing...)
			install := runCommand(ctx.context, "", "apt-get", args...)
			if install.Err != nil {
				return commandFailure("packages", "не удалось установить пакеты", install)
			}
			return report.Result{Control: "packages", Status: report.Changed, Severity: "high", Message: "пакеты базового профиля установлены", Changed: true, Details: map[string]string{"installed": strings.Join(missing, ", ")}}
		},
	}
}

func requiredPackages(ctx *serverContext) []string {
	packages := []string{"ca-certificates", "iproute2", "sudo"}
	server := ctx.config.Server
	if server.ManageSSH {
		packages = append(packages, "openssh-server")
	}
	if server.ManageFirewall {
		packages = append(packages, "ufw")
	}
	if server.ManageFail2ban {
		packages = append(packages, "fail2ban")
	}
	if server.ManageAutomaticUpdates {
		packages = append(packages, "unattended-upgrades")
	}
	if server.ManageAuditd {
		packages = append(packages, "auditd")
	}
	if server.ManageAppArmor {
		packages = append(packages, "apparmor", "apparmor-utils")
	}
	if server.ManageTimeSync {
		packages = append(packages, "chrony")
	}
	sort.Strings(packages)
	unique := packages[:0]
	for _, item := range packages {
		if len(unique) == 0 || unique[len(unique)-1] != item {
			unique = append(unique, item)
		}
	}
	return unique
}

func missingPackages(ctx *serverContext, packages []string) []string {
	missing := make([]string, 0)
	for _, name := range packages {
		result := runCommand(ctx.context, "", "dpkg-query", "-W", "-f=${db:Status-Abbrev}", name)
		if result.Err != nil || result.Stdout != "ii" {
			missing = append(missing, name)
		}
	}
	return missing
}

func automaticUpdatesControl() control {
	const path = "/etc/apt/apt.conf.d/52bastionctl-unattended-upgrades"
	return managedTextControl(
		"automatic-updates",
		func(ctx *serverContext) bool { return ctx.config.Server.ManageAutomaticUpdates },
		path,
		func(ctx *serverContext) string {
			s := ctx.config.Server
			return fmt.Sprintf("// Managed by bastionctl.\nAPT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\nUnattended-Upgrade::Automatic-Reboot \"%t\";\nUnattended-Upgrade::Automatic-Reboot-Time \"%s\";\n", s.AutomaticReboot, s.AutomaticRebootTime)
		},
		0o644,
		"включить ежедневную установку обновлений безопасности",
		func(ctx *serverContext) error {
			result := runCommand(ctx.context, "", "apt-config", "dump")
			if result.Err != nil {
				return fmt.Errorf("apt-config: %s", firstError(result))
			}
			return nil
		},
		func(ctx *serverContext) error {
			result := runCommand(ctx.context, "", "systemctl", "enable", "--now", "unattended-upgrades.service")
			if result.Err != nil {
				return fmt.Errorf("systemctl: %s", firstError(result))
			}
			return nil
		},
	)
}

func sysctlControl() control {
	const path = "/etc/sysctl.d/99-bastionctl.conf"
	return managedTextControl(
		"sysctl",
		func(ctx *serverContext) bool { return ctx.config.Server.ManageSysctl },
		path,
		func(ctx *serverContext) string {
			rp := strconv.Itoa(ctx.config.Server.RPFilter)
			return "# Managed by bastionctl.\n" +
				"kernel.kptr_restrict = 2\n" +
				"kernel.dmesg_restrict = 1\n" +
				"kernel.yama.ptrace_scope = 1\n" +
				"fs.protected_hardlinks = 1\n" +
				"fs.protected_symlinks = 1\n" +
				"fs.protected_fifos = 2\n" +
				"fs.protected_regular = 2\n" +
				"net.ipv4.conf.all.rp_filter = " + rp + "\n" +
				"net.ipv4.conf.default.rp_filter = " + rp + "\n" +
				"net.ipv4.conf.all.accept_redirects = 0\n" +
				"net.ipv4.conf.default.accept_redirects = 0\n" +
				"net.ipv4.conf.all.send_redirects = 0\n" +
				"net.ipv4.conf.default.send_redirects = 0\n" +
				"net.ipv4.conf.all.accept_source_route = 0\n" +
				"net.ipv4.conf.default.accept_source_route = 0\n" +
				"net.ipv6.conf.all.accept_redirects = 0\n" +
				"net.ipv6.conf.default.accept_redirects = 0\n" +
				"net.ipv6.conf.all.accept_source_route = 0\n" +
				"net.ipv6.conf.default.accept_source_route = 0\n"
		},
		0o644,
		"записать консервативные kernel/network sysctl без отключения IPv6 и forwarding",
		nil,
		func(ctx *serverContext) error {
			result := runCommand(ctx.context, "", "sysctl", "--system")
			if result.Err != nil {
				return fmt.Errorf("sysctl --system: %s", firstError(result))
			}
			return nil
		},
	)
}

func journaldControl() control {
	const path = "/etc/systemd/journald.conf.d/60-bastionctl.conf"
	return managedTextControl(
		"journald",
		func(ctx *serverContext) bool { return ctx.config.Server.ManageJournald },
		path,
		func(ctx *serverContext) string {
			return "# Managed by bastionctl.\n[Journal]\nStorage=persistent\nCompress=yes\nSeal=yes\nSystemMaxUse=" + ctx.config.Server.JournalMaxUse + "\n"
		},
		0o644,
		"включить постоянный журнал с ограничением размера",
		func(ctx *serverContext) error {
			if _, err := findCommand("systemd-analyze"); err != nil {
				return nil
			}
			result := runCommand(ctx.context, "", "systemd-analyze", "cat-config", "systemd/journald.conf")
			if result.Err != nil {
				return fmt.Errorf("systemd-analyze: %s", firstError(result))
			}
			return nil
		},
		func(ctx *serverContext) error {
			if err := os.MkdirAll("/var/log/journal", 0o2755); err != nil {
				return err
			}
			result := runCommand(ctx.context, "", "systemctl", "restart", "systemd-journald.service")
			if result.Err != nil {
				return fmt.Errorf("systemctl: %s", firstError(result))
			}
			return nil
		},
	)
}

func auditdControl() control {
	const path = "/etc/audit/rules.d/60-bastionctl.rules"
	const rules = "# Managed by bastionctl.\n-w /etc/passwd -p wa -k identity\n-w /etc/group -p wa -k identity\n-w /etc/shadow -p wa -k identity\n-w /etc/gshadow -p wa -k identity\n-w /etc/sudoers -p wa -k sudoers\n-w /etc/sudoers.d -p wa -k sudoers\n-w /etc/ssh/sshd_config -p wa -k sshd\n-w /etc/ssh/sshd_config.d -p wa -k sshd\n-w /var/log/lastlog -p wa -k logins\n"
	return managedTextControl(
		"auditd",
		func(ctx *serverContext) bool { return ctx.config.Server.ManageAuditd },
		path,
		func(_ *serverContext) string { return rules },
		0o640,
		"установить audit rules для учётных данных, sudo и SSH",
		func(ctx *serverContext) error {
			result := runCommand(ctx.context, "", "augenrules", "--check")
			if result.Err != nil {
				return fmt.Errorf("augenrules --check: %s", firstError(result))
			}
			return nil
		},
		func(ctx *serverContext) error {
			load := runCommand(ctx.context, "", "augenrules", "--load")
			if load.Err != nil {
				return fmt.Errorf("augenrules --load: %s", firstError(load))
			}
			enable := runCommand(ctx.context, "", "systemctl", "enable", "--now", "auditd.service")
			if enable.Err != nil {
				return fmt.Errorf("systemctl: %s", firstError(enable))
			}
			return nil
		},
	)
}

func apparmorControl() control {
	return serviceControl(
		"apparmor",
		func(ctx *serverContext) bool { return ctx.config.Server.ManageAppArmor },
		"apparmor.service",
		"включить AppArmor и проверить, что LSM активен",
		func(ctx *serverContext) error {
			result := runCommand(ctx.context, "", "aa-status", "--enabled")
			if result.Err != nil {
				return fmt.Errorf("aa-status: %s", firstError(result))
			}
			return nil
		},
	)
}

func timeSyncControl() control {
	return serviceControl(
		"time-sync",
		func(ctx *serverContext) bool { return ctx.config.Server.ManageTimeSync },
		"chrony.service",
		"включить chrony для корректного времени журналов и сертификатов",
		func(ctx *serverContext) error {
			result := runCommand(ctx.context, "", "chronyc", "tracking")
			if result.Err != nil {
				return fmt.Errorf("chronyc tracking: %s", firstError(result))
			}
			return nil
		},
	)
}

type controlValidator func(*serverContext) error

func managedTextControl(name string, enabled func(*serverContext) bool, path string, desired func(*serverContext) string, mode os.FileMode, planMessage string, validate, activate controlValidator) control {
	return functionalControl{
		name:    name,
		enabled: enabled,
		audit: func(ctx *serverContext) []report.Result {
			content, err := os.ReadFile(path)
			if err != nil {
				if os.IsNotExist(err) {
					return []report.Result{{Control: name, Status: report.Fail, Severity: "high", Message: "управляемый файл отсутствует", Details: map[string]string{"path": path}}}
				}
				return []report.Result{failResult(name, "не удалось прочитать управляемый файл", err)}
			}
			if string(content) != desired(ctx) {
				return []report.Result{{Control: name, Status: report.Fail, Severity: "high", Message: "управляемый файл отличается от политики", Details: map[string]string{"path": path}}}
			}
			return []report.Result{{Control: name, Status: report.Pass, Severity: "high", Message: "управляемый файл соответствует политике", Details: map[string]string{"path": path}}}
		},
		plan: func(_ *serverContext) report.Result {
			return report.Result{Control: name, Status: report.Planned, Severity: "high", Message: planMessage, Details: map[string]string{"path": path}}
		},
		preflight: func(_ *serverContext) []report.Result {
			if err := preflightManagedPath(path); err != nil {
				return []report.Result{{Status: report.Fail, Severity: "critical", Message: err.Error(), Details: map[string]string{"path": path}}}
			}
			return []report.Result{{Status: report.Pass, Severity: "high", Message: "целевой путь безопасен", Details: map[string]string{"path": path}}}
		},
		apply: func(ctx *serverContext) report.Result {
			wanted := desired(ctx)
			current, readErr := os.ReadFile(path)
			changed := readErr != nil || string(current) != wanted
			if !changed {
				if activate != nil {
					if err := activate(ctx); err != nil {
						return failResult(name, "конфигурация записана, но активация завершилась с ошибкой", err)
					}
				}
				return report.Result{Control: name, Status: report.Pass, Severity: "high", Message: "конфигурация уже соответствует политике"}
			}
			snapshot, err := snapshotFile(path, ctx.backupRoot, name)
			if err != nil {
				return failResult(name, "не удалось создать резервную копию", err)
			}
			if err := snapshot.Write([]byte(wanted), mode); err != nil {
				return failResult(name, "не удалось атомарно записать конфигурацию", err)
			}
			if validate != nil {
				if err := validate(ctx); err != nil {
					restoreErr := snapshot.Restore()
					return rollbackFailure(name, "валидатор отклонил конфигурацию", err, restoreErr)
				}
			}
			if activate != nil {
				if err := activate(ctx); err != nil {
					restoreErr := snapshot.Restore()
					if restoreErr == nil {
						if validate != nil {
							_ = validate(ctx)
						}
						if reactivateErr := activate(ctx); reactivateErr != nil {
							restoreErr = fmt.Errorf("файл восстановлен, но прежнее состояние не активировано: %w", reactivateErr)
						}
					}
					return rollbackFailure(name, "активация конфигурации завершилась с ошибкой", err, restoreErr)
				}
			}
			return report.Result{Control: name, Status: report.Changed, Severity: "high", Message: "конфигурация применена", Changed: true, Details: map[string]string{"path": path}}
		},
	}
}

func serviceControl(name string, enabled func(*serverContext) bool, unit, planMessage string, verify controlValidator) control {
	return functionalControl{
		name:    name,
		enabled: enabled,
		audit: func(ctx *serverContext) []report.Result {
			active := runCommand(ctx.context, "", "systemctl", "is-active", unit)
			if active.Err != nil {
				return []report.Result{{Control: name, Status: report.Fail, Severity: "high", Message: "сервис не активен", Details: map[string]string{"unit": unit, "state": firstError(active)}}}
			}
			if verify != nil {
				if err := verify(ctx); err != nil {
					return []report.Result{failResult(name, "дополнительная проверка сервиса не пройдена", err)}
				}
			}
			return []report.Result{{Control: name, Status: report.Pass, Severity: "high", Message: "сервис активен", Details: map[string]string{"unit": unit}}}
		},
		plan: func(_ *serverContext) report.Result {
			return report.Result{Control: name, Status: report.Planned, Severity: "high", Message: planMessage, Details: map[string]string{"unit": unit}}
		},
		apply: func(ctx *serverContext) report.Result {
			activeBefore := runCommand(ctx.context, "", "systemctl", "is-active", unit).Err == nil
			enabledBefore := runCommand(ctx.context, "", "systemctl", "is-enabled", unit).Err == nil
			if activeBefore && enabledBefore {
				if verify != nil {
					if err := verify(ctx); err != nil {
						return failResult(name, "сервис активен, но проверка не пройдена", err)
					}
				}
				return report.Result{Control: name, Status: report.Pass, Severity: "high", Message: "сервис уже включён и проверен", Details: map[string]string{"unit": unit}}
			}
			result := runCommand(ctx.context, "", "systemctl", "enable", "--now", unit)
			if result.Err != nil {
				return commandFailure(name, "не удалось включить сервис", result)
			}
			if verify != nil {
				if err := verify(ctx); err != nil {
					return failResult(name, "сервис включён, но проверка не пройдена", err)
				}
			}
			return report.Result{Control: name, Status: report.Changed, Severity: "high", Message: "сервис включён и проверен", Changed: true, Details: map[string]string{"unit": unit}}
		},
	}
}

func rollbackFailure(name, message string, original, restore error) report.Result {
	details := map[string]string{"error": original.Error()}
	if restore != nil {
		details["rollback_error"] = restore.Error()
		message += "; откат также завершился с ошибкой"
	} else {
		details["rollback"] = "исходный файл восстановлен"
	}
	return report.Result{Control: name, Status: report.Fail, Severity: "critical", Message: message, Details: details}
}
