//go:build linux

package server

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"bastionctl/internal/report"
)

func accountsControl() control {
	return functionalControl{
		name: "accounts",
		audit: func(_ *serverContext) []report.Result {
			file, err := os.Open("/etc/passwd")
			if err != nil {
				return []report.Result{failResult("accounts", "не удалось прочитать /etc/passwd", err)}
			}
			defer file.Close()
			uidZero := make([]string, 0)
			interactive := make([]string, 0)
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				fields := strings.Split(scanner.Text(), ":")
				if len(fields) < 7 {
					continue
				}
				uid, parseErr := strconv.Atoi(fields[2])
				if parseErr != nil {
					continue
				}
				if uid == 0 {
					uidZero = append(uidZero, fields[0])
				}
				shell := fields[6]
				if shell != "/usr/sbin/nologin" && shell != "/sbin/nologin" && shell != "/bin/false" && shell != "/usr/bin/false" {
					interactive = append(interactive, fields[0])
				}
			}
			if err := scanner.Err(); err != nil {
				return []report.Result{failResult("accounts", "ошибка чтения /etc/passwd", err)}
			}
			results := make([]report.Result, 0, 2)
			if len(uidZero) == 1 && uidZero[0] == "root" {
				results = append(results, report.Result{Control: "accounts", Status: report.Pass, Severity: "critical", Message: "единственная учётная запись UID 0 — root"})
			} else {
				results = append(results, report.Result{Control: "accounts", Status: report.Fail, Severity: "critical", Message: "обнаружены дополнительные или необычные учётные записи UID 0", Details: map[string]string{"users": strings.Join(uidZero, ", ")}})
			}
			sort.Strings(interactive)
			results = append(results, report.Result{Control: "accounts", Status: report.Info, Severity: "medium", Message: "учётные записи с интерактивной оболочкой требуют ручной проверки", Details: map[string]string{"users": strings.Join(interactive, ", ")}})
			return results
		},
		plan: func(_ *serverContext) report.Result {
			return report.Result{Control: "accounts", Status: report.Info, Severity: "high", Message: "показать UID 0 и интерактивные учётные записи; пользователей автоматически не удалять"}
		},
	}
}

func exposureControl() control {
	return functionalControl{
		name: "exposure",
		audit: func(ctx *serverContext) []report.Result {
			result := runCommand(ctx.context, "", "ss", "-H", "-lntup")
			if result.Err != nil {
				return []report.Result{commandFailure("exposure", "не удалось получить listening sockets", result)}
			}
			allowed := map[int]struct{}{}
			for _, port := range append(append([]int{}, ctx.config.Server.AllowedTCPPorts...), ctx.config.Server.AllowedUDPPorts...) {
				allowed[port] = struct{}{}
			}
			if len(ctx.sshPorts) == 0 {
				_, ports, _ := effectiveSSH(ctx)
				ctx.sshPorts = ports
			}
			for _, port := range ctx.sshPorts {
				allowed[port] = struct{}{}
			}
			unexpected := make([]string, 0)
			for _, line := range strings.Split(result.Stdout, "\n") {
				fields := strings.Fields(line)
				if len(fields) < 5 {
					continue
				}
				local := fields[4]
				if !isWildcardAddress(local) {
					continue
				}
				port, ok := trailingPort(local)
				if !ok {
					continue
				}
				if _, expected := allowed[port]; !expected {
					unexpected = append(unexpected, limitText(line, 300))
				}
			}
			results := make([]report.Result, 0, 2)
			if len(unexpected) == 0 {
				results = append(results, report.Result{Control: "exposure", Status: report.Pass, Severity: "high", Message: "неожиданные wildcard listeners не обнаружены"})
			} else {
				results = append(results, report.Result{Control: "exposure", Status: report.Warn, Severity: "high", Message: "обнаружены wildcard listeners вне разрешённого профиля", Details: map[string]string{"listeners": strings.Join(unexpected, " | ")}})
			}
			if _, err := findCommand("docker"); err == nil {
				docker := runCommand(ctx.context, "", "docker", "ps", "--format", "{{.Names}} {{.Ports}}")
				if docker.Err == nil && (strings.Contains(docker.Stdout, "0.0.0.0:") || strings.Contains(docker.Stdout, ":::") || strings.Contains(docker.Stdout, "[::]:")) {
					results = append(results, report.Result{Control: "docker-exposure", Status: report.Warn, Severity: "high", Message: "Docker публикует порты; они могут обходить обычный путь UFW", Details: map[string]string{"published": limitText(docker.Stdout, 2000)}})
				}
			}
			return results
		},
		plan: func(_ *serverContext) report.Result {
			return report.Result{Control: "exposure", Status: report.Info, Severity: "high", Message: "инвентаризировать wildcard listeners и Docker published ports без автоматического закрытия"}
		},
	}
}

func operationsControl() control {
	return functionalControl{
		name: "operations",
		audit: func(_ *serverContext) []report.Result {
			return []report.Result{{Control: "operations", Status: report.Warn, Severity: "critical", Message: "нужны внешние меры, которые нельзя доказать с сервера", Details: map[string]string{"manual": "проверенное восстановление backup; MFA и rescue-консоль провайдера; cloud firewall; обновления приложений; шифрование и защита ключей"}}}
		},
		plan: func(_ *serverContext) report.Result {
			return report.Result{Control: "operations", Status: report.Info, Severity: "critical", Message: "зафиксировать владельца backup, rescue, MFA, cloud firewall и теста восстановления"}
		},
	}
}

func firewallControl() control {
	return functionalControl{
		name:    "firewall",
		enabled: func(ctx *serverContext) bool { return ctx.config.Server.ManageFirewall },
		audit: func(ctx *serverContext) []report.Result {
			result := runCommand(ctx.context, "", "ufw", "status", "verbose")
			if result.Err != nil {
				return []report.Result{commandFailure("firewall", "не удалось получить статус UFW", result)}
			}
			lower := strings.ToLower(result.Stdout)
			failures := make([]string, 0)
			if !strings.Contains(lower, "status: active") {
				failures = append(failures, "UFW не активен")
			}
			if !strings.Contains(lower, "default: deny (incoming)") || !strings.Contains(lower, "allow (outgoing)") {
				failures = append(failures, "default policy не deny incoming / allow outgoing")
			}
			if len(ctx.sshPorts) == 0 {
				_, ports, _ := effectiveSSH(ctx)
				ctx.sshPorts = ports
			}
			for _, port := range ctx.sshPorts {
				if !strings.Contains(result.Stdout, strconv.Itoa(port)+"/tcp") && !regexp.MustCompile(`(?m)^`+strconv.Itoa(port)+`\s`).MatchString(result.Stdout) {
					failures = append(failures, fmt.Sprintf("нет видимого правила SSH для порта %d", port))
				}
			}
			if len(failures) > 0 {
				return []report.Result{{Control: "firewall", Status: report.Fail, Severity: "critical", Message: "UFW не соответствует базовой политике", Details: map[string]string{"issues": strings.Join(failures, "; ")}}}
			}
			return []report.Result{{Control: "firewall", Status: report.Pass, Severity: "critical", Message: "UFW активен, default policy и SSH-правила обнаружены"}}
		},
		plan: func(ctx *serverContext) report.Result {
			ports := ctx.sshPorts
			if len(ports) == 0 {
				_, ports, _ = effectiveSSH(ctx)
			}
			return report.Result{Control: "firewall", Status: report.Planned, Severity: "critical", Message: "сначала добавить SSH allow, затем сервисные порты, deny incoming / allow outgoing и включить UFW; существующие правила не удалять", Details: map[string]string{"ssh_ports": joinInts(ports), "ssh_sources": strings.Join(ctx.config.Server.SSHAllowedCIDRs, ","), "tcp_ports": joinInts(ctx.config.Server.AllowedTCPPorts), "udp_ports": joinInts(ctx.config.Server.AllowedUDPPorts)}}
		},
		preflight: func(ctx *serverContext) []report.Result {
			return firewallPreflight(ctx)
		},
		apply: func(ctx *serverContext) report.Result {
			checks := firewallPreflight(ctx)
			for _, check := range checks {
				if check.Status == report.Fail {
					return report.Result{Control: "firewall", Status: report.Fail, Severity: "critical", Message: "firewall preflight изменился после установки пакетов; UFW не включён", Details: check.Details}
				}
			}
			commands := firewallCommands(ctx)
			for _, command := range commands {
				result := runCommand(ctx.context, "", "ufw", command...)
				if result.Err != nil {
					return report.Result{Control: "firewall", Status: report.Fail, Severity: "critical", Message: "команда UFW завершилась с ошибкой; добавленные правила автоматически не удаляются", Details: map[string]string{"command": strings.Join(command, " "), "error": firstError(result)}}
				}
			}
			status := runCommand(ctx.context, "", "ufw", "status", "verbose")
			if status.Err != nil || !strings.Contains(strings.ToLower(status.Stdout), "status: active") {
				return commandFailure("firewall", "UFW не подтвердил активное состояние", status)
			}
			return report.Result{Control: "firewall", Status: report.Changed, Severity: "critical", Message: "SSH allow добавлен до включения UFW; firewall активен", Changed: true, Details: map[string]string{"ssh_ports": joinInts(ctx.sshPorts), "note": "существующие правила сохранены; проверьте ufw status numbered"}}
		},
	}
}

func firewallPreflight(ctx *serverContext) []report.Result {
	results := make([]report.Result, 0)
	_, ports, err := effectiveSSH(ctx)
	if err != nil || len(ports) == 0 {
		if err == nil {
			err = fmt.Errorf("sshd не сообщил порты")
		}
		return []report.Result{{Status: report.Fail, Severity: "critical", Message: "не удалось определить эффективные SSH-порты", Details: map[string]string{"error": err.Error()}}}
	}
	ctx.sshPorts = ports
	clientIP, serverPort, remote := currentSSHConnection()
	if remote {
		if !containsInt(ports, serverPort) {
			return []report.Result{{Status: report.Fail, Severity: "critical", Message: "порт текущей SSH-сессии отсутствует в эффективной конфигурации sshd", Details: map[string]string{"session_port": strconv.Itoa(serverPort), "effective_ports": joinInts(ports)}}}
		}
		if len(ctx.config.Server.SSHAllowedCIDRs) > 0 && !ipAllowed(clientIP, ctx.config.Server.SSHAllowedCIDRs) {
			return []report.Result{{Status: report.Fail, Severity: "critical", Message: "IP текущего администратора не входит в ssh_allowed_cidrs", Details: map[string]string{"client_ip": clientIP.String(), "cidrs": strings.Join(ctx.config.Server.SSHAllowedCIDRs, ",")}}}
		}
		results = append(results, report.Result{Status: report.Pass, Severity: "critical", Message: "текущая SSH-сессия сохранит разрешённый порт и источник", Details: map[string]string{"client_ip": clientIP.String(), "port": strconv.Itoa(serverPort)}})
	} else {
		results = append(results, report.Result{Status: report.Warn, Severity: "high", Message: "SSH_CONNECTION отсутствует; предполагается локальная/rescue-консоль, источник проверить автоматически нельзя"})
	}
	if needsIPv6(ctx) {
		content, readErr := os.ReadFile("/etc/default/ufw")
		if readErr == nil && !regexp.MustCompile(`(?m)^IPV6\s*=\s*yes\s*$`).Match(content) {
			return append(results, report.Result{Status: report.Fail, Severity: "critical", Message: "IPv6 используется, но /etc/default/ufw не содержит IPV6=yes"})
		}
	}
	if _, lookupErr := findCommand("ufw"); lookupErr != nil {
		results = append(results, report.Result{Status: report.Info, Severity: "medium", Message: "UFW будет установлен пакетным контролем до применения firewall"})
	} else {
		status := runCommand(ctx.context, "", "ufw", "status", "numbered")
		if status.Err == nil {
			for _, line := range strings.Split(status.Stdout, "\n") {
				upper := strings.ToUpper(line)
				if !strings.Contains(upper, "DENY IN") && !strings.Contains(upper, "REJECT IN") {
					continue
				}
				for _, port := range ports {
					if regexp.MustCompile(`(^|[^0-9])` + strconv.Itoa(port) + `([^0-9]|$)`).MatchString(line) {
						return append(results, report.Result{Status: report.Fail, Severity: "critical", Message: "существующее deny/reject правило может перекрыть новый SSH allow; требуется ручная проверка порядка", Details: map[string]string{"rule": strings.TrimSpace(line)}})
					}
				}
			}
		}
	}
	results = append(results, report.Result{Status: report.Pass, Severity: "critical", Message: "firewall preflight пройден", Details: map[string]string{"ssh_ports": joinInts(ports)}})
	return results
}

func firewallCommands(ctx *serverContext) [][]string {
	commands := make([][]string, 0)
	for _, port := range ctx.sshPorts {
		if len(ctx.config.Server.SSHAllowedCIDRs) == 0 {
			commands = append(commands, []string{"allow", fmt.Sprintf("%d/tcp", port), "comment", "bastionctl-ssh"})
		} else {
			for _, cidr := range ctx.config.Server.SSHAllowedCIDRs {
				commands = append(commands, []string{"allow", "proto", "tcp", "from", cidr, "to", "any", "port", strconv.Itoa(port), "comment", "bastionctl-ssh"})
			}
		}
	}
	for _, port := range ctx.config.Server.AllowedTCPPorts {
		commands = append(commands, []string{"allow", fmt.Sprintf("%d/tcp", port), "comment", "bastionctl-service"})
	}
	for _, port := range ctx.config.Server.AllowedUDPPorts {
		commands = append(commands, []string{"allow", fmt.Sprintf("%d/udp", port), "comment", "bastionctl-service"})
	}
	commands = append(commands,
		[]string{"default", "deny", "incoming"},
		[]string{"default", "allow", "outgoing"},
		[]string{"logging", "medium"},
		[]string{"--force", "enable"},
	)
	return commands
}

func currentSSHConnection() (net.IP, int, bool) {
	fields := strings.Fields(os.Getenv("SSH_CONNECTION"))
	if len(fields) != 4 {
		return nil, 0, false
	}
	ip := net.ParseIP(fields[0])
	port, err := strconv.Atoi(fields[3])
	if ip == nil || err != nil || port < 1 || port > 65535 {
		return nil, 0, false
	}
	return ip, port, true
}

func ipAllowed(ip net.IP, cidrs []string) bool {
	for _, value := range cidrs {
		_, network, err := net.ParseCIDR(value)
		if err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

func needsIPv6(ctx *serverContext) bool {
	for _, cidr := range ctx.config.Server.SSHAllowedCIDRs {
		ip, _, _ := net.ParseCIDR(cidr)
		if ip != nil && ip.To4() == nil {
			return true
		}
	}
	content, err := os.ReadFile("/proc/net/if_inet6")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(strings.TrimSpace(string(content)), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 6 && fields[5] != "lo" {
			return true
		}
	}
	return false
}

func containsInt(values []int, expected int) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func isWildcardAddress(value string) bool {
	return strings.HasPrefix(value, "0.0.0.0:") || strings.HasPrefix(value, "[::]:") || strings.HasPrefix(value, "*:") || strings.HasPrefix(value, ":::")
}

func trailingPort(value string) (int, bool) {
	index := strings.LastIndex(value, ":")
	if index < 0 || index == len(value)-1 {
		return 0, false
	}
	port, err := strconv.Atoi(strings.Trim(value[index+1:], "[]"))
	return port, err == nil && port > 0 && port <= 65535
}
