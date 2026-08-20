//go:build linux

package server

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"bastionctl/internal/config"
	"bastionctl/internal/report"
)

type serverContext struct {
	context    context.Context
	config     config.Config
	version    string
	options    Options
	distro     distribution
	backupRoot string
	sshPorts   []int
	adminUser  string
}

type distribution struct {
	ID         string
	VersionID  string
	PrettyName string
	Supported  bool
}

type control interface {
	Name() string
	Enabled(*serverContext) bool
	Audit(*serverContext) []report.Result
	Plan(*serverContext) report.Result
	Preflight(*serverContext) []report.Result
	Apply(*serverContext) report.Result
}

type functionalControl struct {
	name      string
	enabled   func(*serverContext) bool
	audit     func(*serverContext) []report.Result
	plan      func(*serverContext) report.Result
	preflight func(*serverContext) []report.Result
	apply     func(*serverContext) report.Result
}

func (c functionalControl) Name() string { return c.name }

func (c functionalControl) Enabled(ctx *serverContext) bool {
	return c.enabled == nil || c.enabled(ctx)
}

func (c functionalControl) Audit(ctx *serverContext) []report.Result {
	if c.audit == nil {
		return []report.Result{{Control: c.name, Status: report.Info, Severity: "low", Message: "аудит для контроля не требуется"}}
	}
	return c.audit(ctx)
}

func (c functionalControl) Plan(ctx *serverContext) report.Result {
	if c.plan == nil {
		return report.Result{Control: c.name, Status: report.Planned, Severity: "medium", Message: "проверить состояние без автоматических изменений"}
	}
	return c.plan(ctx)
}

func (c functionalControl) Preflight(ctx *serverContext) []report.Result {
	if c.preflight == nil {
		return nil
	}
	return c.preflight(ctx)
}

func (c functionalControl) Apply(ctx *serverContext) report.Result {
	if c.apply == nil {
		results := c.Audit(ctx)
		if len(results) == 0 {
			return report.Result{Control: c.name, Status: report.Skipped, Severity: "low", Message: "read-only проверка не вернула результатов"}
		}
		worst := report.Info
		severity := "low"
		messages := make([]string, 0, len(results))
		for _, result := range results {
			if statusRank(result.Status) > statusRank(worst) {
				worst = result.Status
				severity = result.Severity
			}
			messages = append(messages, string(result.Status)+": "+result.Message)
		}
		return report.Result{Control: c.name, Status: worst, Severity: severity, Message: "read-only проверка: " + strings.Join(messages, "; ")}
	}
	return c.apply(ctx)
}

func statusRank(status report.Status) int {
	switch status {
	case report.Fail:
		return 6
	case report.Warn:
		return 5
	case report.Changed:
		return 4
	case report.Pass:
		return 3
	case report.Planned:
		return 2
	case report.Info:
		return 1
	default:
		return 0
	}
}

func runPlatform(ctx context.Context, cfg config.Config, version string, options Options) *report.Report {
	r := report.New(version, "server", options.Action, "localhost")
	if options.Action != "audit" && options.Action != "plan" && options.Action != "apply" {
		r.Add(report.Result{Control: "arguments", Status: report.Fail, Severity: "critical", Message: "действие должно быть audit, plan или apply"})
		return r
	}
	distro := readDistribution()
	serverCtx := &serverContext{context: ctx, config: cfg, version: version, options: options, distro: distro}
	controls := allControls()

	switch options.Action {
	case "audit":
		for _, item := range controls {
			if !item.Enabled(serverCtx) {
				r.Add(report.Result{Control: item.Name(), Status: report.Skipped, Severity: "low", Message: "управление отключено конфигурацией"})
				continue
			}
			for _, result := range item.Audit(serverCtx) {
				r.Add(result)
			}
		}
	case "plan":
		for _, item := range controls {
			if !item.Enabled(serverCtx) {
				r.Add(report.Result{Control: item.Name(), Status: report.Skipped, Severity: "low", Message: "управление отключено конфигурацией"})
				continue
			}
			r.Add(item.Plan(serverCtx))
			for _, result := range item.Preflight(serverCtx) {
				if result.Status == report.Fail || result.Status == report.Warn {
					result.Control = item.Name() + ".preflight"
					r.Add(result)
				}
			}
		}
	case "apply":
		if !options.Yes {
			r.Add(report.Result{Control: "confirmation", Status: report.Fail, Severity: "critical", Message: "server apply требует явный флаг --yes"})
			return r
		}
		if os.Geteuid() != 0 {
			r.Add(report.Result{Control: "privileges", Status: report.Fail, Severity: "critical", Message: "server apply должен выполняться от root"})
			return r
		}
		if !distro.Supported {
			r.Add(report.Result{Control: "platform", Status: report.Fail, Severity: "critical", Message: "apply поддерживает только Debian/Ubuntu с systemd и apt"})
			return r
		}
		lock, err := acquireLock()
		if err != nil {
			r.Add(report.Result{Control: "process-lock", Status: report.Fail, Severity: "critical", Message: err.Error()})
			return r
		}
		defer lock.Close()

		blocked := false
		for _, item := range controls {
			if !item.Enabled(serverCtx) {
				continue
			}
			for _, result := range item.Preflight(serverCtx) {
				result.Control = item.Name() + ".preflight"
				r.Add(result)
				if result.Status == report.Fail {
					blocked = true
				}
			}
		}
		if blocked {
			r.Add(report.Result{Control: "apply", Status: report.Fail, Severity: "critical", Message: "изменения не начаты: preflight обнаружил блокирующие ошибки"})
			return r
		}
		backupRoot, err := newBackupRoot()
		if err != nil {
			r.Add(report.Result{Control: "backup", Status: report.Fail, Severity: "critical", Message: "не удалось создать каталог резервных копий", Details: map[string]string{"error": err.Error()}})
			return r
		}
		serverCtx.backupRoot = backupRoot
		r.BackupDir = backupRoot
		for _, item := range controls {
			if !item.Enabled(serverCtx) {
				r.Add(report.Result{Control: item.Name(), Status: report.Skipped, Severity: "low", Message: "управление отключено конфигурацией"})
				continue
			}
			result := item.Apply(serverCtx)
			r.Add(result)
			if result.Status == report.Fail {
				r.Add(report.Result{Control: "apply", Status: report.Fail, Severity: "critical", Message: "выполнение остановлено; firewall не будет включён после ошибки предыдущего контроля"})
				break
			}
		}
	}
	return r
}

func allControls() []control {
	return []control{
		platformControl(),
		packagesControl(),
		automaticUpdatesControl(),
		sysctlControl(),
		journaldControl(),
		auditdControl(),
		apparmorControl(),
		timeSyncControl(),
		permissionsControl(),
		sshControl(),
		fail2banControl(),
		accountsControl(),
		exposureControl(),
		backupControl(),
		operationsControl(),
		firewallControl(),
	}
}

func readDistribution() distribution {
	result := distribution{}
	file, err := os.Open("/etc/os-release")
	if err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			key, value, found := strings.Cut(scanner.Text(), "=")
			if !found {
				continue
			}
			value = strings.Trim(strings.TrimSpace(value), "\"")
			switch key {
			case "ID":
				result.ID = strings.ToLower(value)
			case "VERSION_ID":
				result.VersionID = value
			case "PRETTY_NAME":
				result.PrettyName = value
			}
		}
	}
	_, aptErr := findCommand("apt-get")
	_, systemdErr := findCommand("systemctl")
	result.Supported = (result.ID == "debian" || result.ID == "ubuntu") && aptErr == nil && systemdErr == nil
	return result
}

func platformControl() control {
	return functionalControl{
		name: "platform",
		audit: func(ctx *serverContext) []report.Result {
			status := report.Pass
			severity := "low"
			message := "поддерживаемая платформа"
			if !ctx.distro.Supported {
				status = report.Warn
				severity = "high"
				message = "платформа доступна только для аудита; apply заблокирован"
			}
			return []report.Result{{Control: "platform", Status: status, Severity: severity, Message: message, Details: map[string]string{"distribution": ctx.distro.PrettyName, "id": ctx.distro.ID, "version": ctx.distro.VersionID}}}
		},
		plan: func(ctx *serverContext) report.Result {
			status := report.Info
			message := "проверить совместимость Debian/Ubuntu, apt и systemd"
			if !ctx.distro.Supported {
				status = report.Fail
				message = "apply будет заблокирован: нужна Debian/Ubuntu с apt и systemd"
			}
			return report.Result{Control: "platform", Status: status, Severity: "critical", Message: message}
		},
		preflight: func(ctx *serverContext) []report.Result {
			if !ctx.distro.Supported {
				return []report.Result{{Status: report.Fail, Severity: "critical", Message: "неподдерживаемая платформа"}}
			}
			return []report.Result{{Status: report.Pass, Severity: "critical", Message: "платформа поддерживается"}}
		},
		apply: func(_ *serverContext) report.Result {
			return report.Result{Control: "platform", Status: report.Pass, Severity: "low", Message: "проверка платформы пройдена"}
		},
	}
}

func sortedUnique(values []int) []int {
	seen := map[int]struct{}{}
	for _, value := range values {
		seen[value] = struct{}{}
	}
	result := make([]int, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Ints(result)
	return result
}

func failResult(controlName, message string, err error) report.Result {
	details := map[string]string{}
	if err != nil {
		details["error"] = limitText(err.Error(), 2000)
	}
	return report.Result{Control: controlName, Status: report.Fail, Severity: "critical", Message: message, Details: details}
}

func commandFailure(controlName, message string, result commandResult) report.Result {
	return failResult(controlName, message, errors.New(firstError(result)))
}

func detailsOf(pairs ...string) map[string]string {
	details := map[string]string{}
	for index := 0; index+1 < len(pairs); index += 2 {
		if pairs[index+1] != "" {
			details[pairs[index]] = pairs[index+1]
		}
	}
	return details
}

func joinInts(values []int) string {
	parts := make([]string, len(values))
	for index, value := range values {
		parts[index] = fmt.Sprintf("%d", value)
	}
	return strings.Join(parts, ",")
}
