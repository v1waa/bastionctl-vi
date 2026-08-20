package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"bastionctl/internal/admin"
	"bastionctl/internal/config"
	"bastionctl/internal/console"
	"bastionctl/internal/controller"
	"bastionctl/internal/explain"
	"bastionctl/internal/inventory"
	"bastionctl/internal/profile"
	"bastionctl/internal/report"
	"bastionctl/internal/server"
	"bastionctl/internal/state"
)

const (
	exitOK          = 0
	exitFindings    = 2
	exitUsage       = 64
	exitUnavailable = 69
	exitInternal    = 70
	exitPermission  = 77
)

type parsedOptions struct {
	values      map[string]string
	booleans    map[string]bool
	positionals []string
}

func Run(ctx context.Context, args []string, version string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		control, err := controller.New(version, "")
		if err != nil {
			return commandError(stderr, err)
		}
		return console.Run(ctx, control, stdin, stdout, stderr)
	}
	if args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		_, _ = fmt.Fprint(stdout, Help(version))
		return exitOK
	}
	if args[0] == "version" || args[0] == "--version" {
		_, _ = fmt.Fprintln(stdout, version)
		return exitOK
	}
	switch args[0] {
	case "console":
		return runConsole(ctx, args[1:], version, stdin, stdout, stderr)
	case "server":
		if len(args) < 2 {
			return usageError(stderr, "server требует действие")
		}
		return runServer(ctx, args[1], args[2:], version, stdout, stderr)
	case "admin":
		if len(args) < 2 {
			return usageError(stderr, "admin требует действие")
		}
		return runAdmin(ctx, args[1], args[2:], version, stdin, stdout, stderr)
	case "fleet":
		if len(args) < 2 {
			return usageError(stderr, "fleet требует действие")
		}
		return runFleet(ctx, args[1], args[2:], version, stdin, stdout, stderr)
	case "explain":
		return runExplain(args[1:], stdout, stderr)
	default:
		return usageError(stderr, "неизвестная команда "+args[0])
	}
}

func runConsole(ctx context.Context, args []string, version string, stdin io.Reader, stdout, stderr io.Writer) int {
	parsed, err := parse(args, map[string]bool{"--state-dir": true})
	if err != nil {
		return usageError(stderr, err.Error())
	}
	if len(parsed.positionals) != 0 {
		return usageError(stderr, "console не принимает позиционные аргументы")
	}
	control, err := controller.New(version, parsed.values["--state-dir"])
	if err != nil {
		return commandError(stderr, err)
	}
	return console.Run(ctx, control, stdin, stdout, stderr)
}

func runServer(ctx context.Context, action string, args []string, version string, stdout, stderr io.Writer) int {
	if action != "audit" && action != "plan" && action != "apply" && action != "snapshot" {
		return usageError(stderr, "server поддерживает audit, plan, apply и snapshot")
	}
	specification := map[string]bool{"--config": true, "--json": false}
	if action == "apply" {
		specification["--yes"] = false
	}
	parsed, err := parse(args, specification)
	if err != nil {
		return usageError(stderr, err.Error())
	}
	if len(parsed.positionals) != 0 {
		return usageError(stderr, "server не принимает позиционные аргументы")
	}
	configPath := parsed.values["--config"]
	if configPath == "" {
		configPath = "/etc/bastionctl/config.toml"
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		return usageError(stderr, err.Error())
	}
	if action == "snapshot" {
		snapshot, captureErr := server.Capture(ctx, cfg, version, configPath)
		if captureErr != nil {
			return commandError(stderr, captureErr)
		}
		if parsed.booleans["--json"] {
			if err := writeJSON(stdout, snapshot); err != nil {
				return outputError(stderr, err)
			}
		} else {
			writeSnapshotSummary(stdout, snapshot)
		}
		return exitOK
	}
	if action == "apply" && !parsed.booleans["--yes"] {
		return usageError(stderr, "server apply требует --yes после проверки audit и plan")
	}
	r := server.Run(ctx, cfg, version, server.Options{Action: action, ConfigPath: configPath, Yes: parsed.booleans["--yes"]})
	if err := writeReport(stdout, r, parsed.booleans["--json"]); err != nil {
		return outputError(stderr, err)
	}
	if r.HasFailures() {
		if action == "apply" {
			return exitPermission
		}
		return exitFindings
	}
	return exitOK
}

func runAdmin(ctx context.Context, action string, args []string, version string, stdin io.Reader, stdout, stderr io.Writer) int {
	specification, known := adminSpecification(action)
	if !known {
		return usageError(stderr, "admin поддерживает doctor, audit, plan, apply, snapshot и install")
	}
	parsed, err := parse(args, specification)
	if err != nil {
		return usageError(stderr, err.Error())
	}
	cfg := config.Defaults()
	configPath := parsed.values["--config"]
	if configPath != "" {
		cfg, err = config.Load(configPath)
		if err != nil {
			return usageError(stderr, err.Error())
		}
	}
	identity := admin.ExpandIdentity(parsed.values["--identity"])
	port, err := optionPort(parsed.values["--port"])
	if err != nil {
		return usageError(stderr, err.Error())
	}
	jsonOutput := parsed.booleans["--json"]
	if action == "doctor" {
		if len(parsed.positionals) != 0 {
			return usageError(stderr, "admin doctor не принимает target")
		}
		r := admin.Doctor(ctx, cfg.Admin, version, identity)
		return finishAdminReport(r, jsonOutput, stdout, stderr)
	}
	if len(parsed.positionals) != 1 {
		return usageError(stderr, "нужно указать ровно одну цель user@host")
	}
	connection := admin.Options{Action: action, Target: parsed.positionals[0], Port: port, Identity: identity, Yes: parsed.booleans["--yes"]}
	switch action {
	case "snapshot":
		snapshot, err := admin.CaptureSnapshot(ctx, cfg.Admin, version, connection)
		if err != nil {
			return commandError(stderr, err)
		}
		if jsonOutput {
			if err := writeJSON(stdout, snapshot); err != nil {
				return outputError(stderr, err)
			}
		} else {
			writeSnapshotSummary(stdout, snapshot)
		}
		return exitOK
	case "install":
		if configPath == "" || parsed.values["--binary"] == "" {
			return usageError(stderr, "admin install требует --config PATH и --binary PATH")
		}
		r := admin.Install(ctx, cfg.Admin, version, admin.InstallOptions{
			Connection: connection, BinaryPath: parsed.values["--binary"], ConfigPath: configPath,
			InstallSudo: parsed.booleans["--install-sudo"], InteractiveSudo: parsed.booleans["--interactive-sudo"],
			Input: stdin, Output: stderr,
		})
		return finishAdminReport(r, jsonOutput, stdout, stderr)
	default:
		if action == "apply" && !parsed.booleans["--yes"] {
			return usageError(stderr, "admin apply требует --yes после проверки audit и plan")
		}
		r := admin.Run(ctx, cfg.Admin, version, connection)
		return finishAdminReport(r, jsonOutput, stdout, stderr)
	}
}

func adminSpecification(action string) (map[string]bool, bool) {
	specification := map[string]bool{"--json": false, "--config": true, "--identity": true}
	switch action {
	case "doctor":
	case "audit", "plan", "snapshot":
		specification["--port"] = true
	case "apply":
		specification["--port"] = true
		specification["--yes"] = false
	case "install":
		specification["--port"] = true
		specification["--binary"] = true
		specification["--install-sudo"] = false
		specification["--interactive-sudo"] = false
	default:
		return nil, false
	}
	return specification, true
}

func finishAdminReport(r *report.Report, jsonOutput bool, stdout, stderr io.Writer) int {
	if err := writeReport(stdout, r, jsonOutput); err != nil {
		return outputError(stderr, err)
	}
	if r.HasFailures() {
		for _, result := range r.Results {
			if result.Status == report.Fail && (result.Control == "ssh-client" || result.Control == "scp-client" || result.Control == "ssh-keygen" || result.Control == "remote-execution" || result.Control == "remote-report" || result.Control == "connection" || result.Control == "architecture") {
				return exitUnavailable
			}
		}
		return exitFindings
	}
	return exitOK
}

func runFleet(ctx context.Context, action string, args []string, version string, stdin io.Reader, stdout, stderr io.Writer) int {
	specification, known := fleetSpecification(action)
	if !known {
		return usageError(stderr, "неизвестное действие fleet "+action)
	}
	parsed, err := parse(args, specification)
	if err != nil {
		return usageError(stderr, err.Error())
	}
	control, err := controller.New(version, parsed.values["--state-dir"])
	if err != nil {
		return commandError(stderr, err)
	}
	jsonOutput := parsed.booleans["--json"]
	switch action {
	case "list":
		if len(parsed.positionals) != 0 {
			return usageError(stderr, "fleet list не принимает ID")
		}
		servers, err := control.List()
		if err != nil {
			return commandError(stderr, err)
		}
		if jsonOutput {
			if err := writeJSON(stdout, servers); err != nil {
				return outputError(stderr, err)
			}
		} else {
			writeServers(stdout, servers)
		}
		return exitOK
	case "add":
		return fleetAdd(control, parsed, stdout, stderr)
	case "configure":
		return fleetConfigure(control, parsed, stdout, stderr)
	case "remove":
		id, ok := oneID(parsed, stderr)
		if !ok {
			return exitUsage
		}
		if !parsed.booleans["--yes"] {
			return usageError(stderr, "fleet remove требует --yes; удаляется только запись реестра")
		}
		if err := control.RemoveServer(id); err != nil {
			return commandError(stderr, err)
		}
		_, _ = fmt.Fprintln(stdout, "Запись удалена; удалённый сервер и локальная история не изменялись.")
		return exitOK
	case "bootstrap":
		id, ok := oneID(parsed, stderr)
		if !ok {
			return exitUsage
		}
		_, _ = fmt.Fprintln(stderr, "Сверьте показанный OpenSSH fingerprint независимым каналом до ответа yes и ввода пароля; bastionctl пароль не читает и не сохраняет.")
		item, err := control.BootstrapAccess(ctx, id, stdin, stderr)
		if err != nil {
			return commandError(stderr, err)
		}
		if jsonOutput {
			if err := writeJSON(stdout, item); err != nil {
				return outputError(stderr, err)
			}
		} else {
			_, _ = fmt.Fprintf(stdout, "Ключевой SSH-вход проверен: %s\n", item.Target)
		}
		return exitOK
	case "audit", "plan", "apply":
		id, ok := oneID(parsed, stderr)
		if !ok {
			return exitUsage
		}
		if action == "apply" && !parsed.booleans["--yes"] {
			return usageError(stderr, "fleet apply требует --yes после отдельного fleet plan")
		}
		result, err := control.RunAction(ctx, id, action, parsed.booleans["--yes"])
		if err != nil {
			return commandError(stderr, err)
		}
		if err := writeOperation(stdout, result, jsonOutput); err != nil {
			return outputError(stderr, err)
		}
		if result.Report.HasFailures() {
			return exitFindings
		}
		return exitOK
	case "install":
		id, ok := oneID(parsed, stderr)
		if !ok {
			return exitUsage
		}
		result, err := control.Install(ctx, id, parsed.values["--binary"], stdin, stderr, parsed.booleans["--interactive-sudo"])
		if err != nil {
			return commandError(stderr, err)
		}
		if err := writeOperation(stdout, result, jsonOutput); err != nil {
			return outputError(stderr, err)
		}
		if result.Report.HasFailures() {
			return exitFindings
		}
		return exitOK
	case "snapshot":
		id, ok := oneID(parsed, stderr)
		if !ok {
			return exitUsage
		}
		result, err := control.CaptureSnapshot(ctx, id, parsed.booleans["--baseline"])
		if err != nil {
			return commandError(stderr, err)
		}
		if jsonOutput {
			if err := writeJSON(stdout, result); err != nil {
				return outputError(stderr, err)
			}
		} else {
			writeSnapshotSummary(stdout, result.Snapshot)
			if result.BaselineCreated {
				_, _ = fmt.Fprintln(stdout, "Snapshot сохранён как baseline.")
			} else if result.Diff != nil {
				writeDiff(stdout, *result.Diff)
			}
		}
		return exitOK
	case "diff":
		id, ok := oneID(parsed, stderr)
		if !ok {
			return exitUsage
		}
		diff, err := control.Diff(id)
		if err != nil {
			return commandError(stderr, err)
		}
		if jsonOutput {
			if err := writeJSON(stdout, diff); err != nil {
				return outputError(stderr, err)
			}
		} else {
			writeDiff(stdout, diff)
		}
		if len(diff.Changes) > 0 {
			return exitFindings
		}
		return exitOK
	case "baseline":
		id, ok := oneID(parsed, stderr)
		if !ok {
			return exitUsage
		}
		if !parsed.booleans["--yes"] {
			return usageError(stderr, "fleet baseline требует --yes")
		}
		if err := control.SetLatestAsBaseline(id); err != nil {
			return commandError(stderr, err)
		}
		_, _ = fmt.Fprintln(stdout, "Последний подписанный snapshot принят как новый baseline.")
		return exitOK
	case "history":
		id, ok := oneID(parsed, stderr)
		if !ok {
			return exitUsage
		}
		limit := 20
		if raw := parsed.values["--limit"]; raw != "" {
			limit, err = strconv.Atoi(raw)
			if err != nil || limit < 1 || limit > 1000 {
				return usageError(stderr, "--limit должен быть числом 1..1000")
			}
		}
		entries, err := control.Store.History(id, limit)
		if err != nil {
			return commandError(stderr, err)
		}
		if jsonOutput {
			if err := writeJSON(stdout, entries); err != nil {
				return outputError(stderr, err)
			}
		} else {
			writeHistory(stdout, entries)
		}
		return exitOK
	case "audit-all":
		if len(parsed.positionals) != 0 {
			return usageError(stderr, "fleet audit-all не принимает ID")
		}
		results, err := control.AuditAll(ctx)
		if err != nil {
			return commandError(stderr, err)
		}
		if jsonOutput {
			if err := writeJSON(stdout, results); err != nil {
				return outputError(stderr, err)
			}
		} else {
			writeFleetResults(stdout, results)
		}
		for _, item := range results {
			if item.Error != "" || (item.Operation != nil && item.Operation.Report.HasFailures()) {
				return exitFindings
			}
		}
		return exitOK
	case "profiles":
		if len(parsed.positionals) != 0 {
			return usageError(stderr, "fleet profiles не принимает ID")
		}
		profiles := profile.List()
		if jsonOutput {
			if err := writeJSON(stdout, profiles); err != nil {
				return outputError(stderr, err)
			}
		} else {
			for _, item := range profiles {
				_, _ = fmt.Fprintf(stdout, "%-12s %s\n  %s\n", item.Name, item.Title, item.Description)
			}
		}
		return exitOK
	}
	return exitInternal
}

func fleetSpecification(action string) (map[string]bool, bool) {
	specification := map[string]bool{"--state-dir": true, "--json": false}
	add := func(name string, value bool) { specification[name] = value }
	switch action {
	case "list", "profiles", "diff", "audit", "plan", "audit-all", "bootstrap":
	case "add":
		for _, name := range []string{"--name", "--port", "--identity", "--profile", "--ssh-cidrs", "--tcp-ports", "--udp-ports", "--backup-markers", "--backup-max-age", "--server-binary"} {
			add(name, true)
		}
		add("--backup-required", false)
		add("--accept-new-host-key", false)
		add("--password-bootstrap", false)
		add("--admin-user", true)
	case "configure":
		for _, name := range []string{"--name", "--target", "--port", "--identity", "--profile", "--ssh-cidrs", "--tcp-ports", "--udp-ports", "--backup-markers", "--backup-max-age", "--server-binary"} {
			add(name, true)
		}
		for _, name := range []string{"--backup-required", "--backup-optional", "--accept-new-host-key", "--strict-host-key"} {
			add(name, false)
		}
	case "remove", "apply", "baseline":
		add("--yes", false)
	case "install":
		add("--binary", true)
		add("--interactive-sudo", false)
	case "snapshot":
		add("--baseline", false)
	case "history":
		add("--limit", true)
	default:
		return nil, false
	}
	return specification, true
}

func fleetAdd(control *controller.Controller, parsed parsedOptions, stdout, stderr io.Writer) int {
	if len(parsed.positionals) != 2 {
		return usageError(stderr, "fleet add требует ID и USER@HOST")
	}
	port, err := optionPort(parsed.values["--port"])
	if err != nil {
		return usageError(stderr, err.Error())
	}
	tcpPorts, err := parsePortList(parsed.values["--tcp-ports"])
	if err != nil {
		return usageError(stderr, "--tcp-ports: "+err.Error())
	}
	udpPorts, err := parsePortList(parsed.values["--udp-ports"])
	if err != nil {
		return usageError(stderr, "--udp-ports: "+err.Error())
	}
	maxAge := 0
	if raw := parsed.values["--backup-max-age"]; raw != "" {
		maxAge, err = strconv.Atoi(raw)
		if err != nil {
			return usageError(stderr, "--backup-max-age должен быть целым числом часов")
		}
	}
	item, err := control.AddServer(controller.AddOptions{
		ID: parsed.positionals[0], Name: parsed.values["--name"], Target: parsed.positionals[1],
		Port: port, Identity: parsed.values["--identity"], Profile: parsed.values["--profile"],
		SSHAllowedCIDRs: splitList(parsed.values["--ssh-cidrs"]), AdditionalTCPPorts: tcpPorts,
		AdditionalUDPPorts: udpPorts, BackupMarkers: splitList(parsed.values["--backup-markers"]),
		BackupMaxAgeHours: maxAge, BackupRequired: parsed.booleans["--backup-required"],
		ServerBinary: parsed.values["--server-binary"], AcceptNewHostKey: parsed.booleans["--accept-new-host-key"],
		PasswordBootstrap: parsed.booleans["--password-bootstrap"], BootstrapAdminUser: parsed.values["--admin-user"],
	})
	if err != nil {
		return commandError(stderr, err)
	}
	if parsed.booleans["--json"] {
		if err := writeJSON(stdout, item); err != nil {
			return outputError(stderr, err)
		}
	} else {
		_, _ = fmt.Fprintf(stdout, "Сервер %s добавлен. Конфигурация: %s\n", item.ID, item.ConfigPath)
	}
	return exitOK
}

func fleetConfigure(control *controller.Controller, parsed parsedOptions, stdout, stderr io.Writer) int {
	id, ok := oneID(parsed, stderr)
	if !ok {
		return exitUsage
	}
	if parsed.booleans["--backup-required"] && parsed.booleans["--backup-optional"] {
		return usageError(stderr, "нельзя одновременно задать --backup-required и --backup-optional")
	}
	if parsed.booleans["--strict-host-key"] && parsed.booleans["--accept-new-host-key"] {
		return usageError(stderr, "нельзя одновременно задать --strict-host-key и --accept-new-host-key")
	}
	cfg, err := control.Config(id)
	if err != nil {
		return commandError(stderr, err)
	}
	if name := parsed.values["--profile"]; name != "" {
		cfg, err = profile.Apply(name, cfg)
		if err != nil {
			return usageError(stderr, err.Error())
		}
	}
	if raw, set := parsed.values["--ssh-cidrs"]; set {
		cfg.Server.SSHAllowedCIDRs = splitList(raw)
	}
	if raw, set := parsed.values["--tcp-ports"]; set {
		cfg.Server.AllowedTCPPorts, err = parsePortList(raw)
		if err != nil {
			return usageError(stderr, "--tcp-ports: "+err.Error())
		}
	}
	if raw, set := parsed.values["--udp-ports"]; set {
		cfg.Server.AllowedUDPPorts, err = parsePortList(raw)
		if err != nil {
			return usageError(stderr, "--udp-ports: "+err.Error())
		}
	}
	if raw, set := parsed.values["--backup-markers"]; set {
		cfg.Server.BackupMarkers = splitList(raw)
	}
	if raw := parsed.values["--backup-max-age"]; raw != "" {
		cfg.Server.BackupMaxAgeHours, err = strconv.Atoi(raw)
		if err != nil {
			return usageError(stderr, "--backup-max-age должен быть целым числом часов")
		}
	}
	if parsed.booleans["--backup-required"] {
		cfg.Server.BackupRequired = true
	}
	if parsed.booleans["--backup-optional"] {
		cfg.Server.BackupRequired = false
	}
	if parsed.booleans["--strict-host-key"] {
		cfg.Admin.StrictHostKeyChecking = true
	}
	if parsed.booleans["--accept-new-host-key"] {
		cfg.Admin.StrictHostKeyChecking = false
	}
	if err := control.SaveConfig(id, cfg); err != nil {
		return usageError(stderr, err.Error())
	}
	if _, nameSet := parsed.values["--name"]; nameSet || hasAnyValue(parsed, "--target", "--port", "--identity", "--server-binary") {
		item, err := control.Store.Server(id)
		if err != nil {
			return commandError(stderr, err)
		}
		name := item.Name
		if raw, set := parsed.values["--name"]; set {
			name = raw
		}
		target := item.Target
		if raw, set := parsed.values["--target"]; set {
			target = raw
		}
		port := item.Port
		if raw, set := parsed.values["--port"]; set {
			port, err = optionPort(raw)
			if err != nil {
				return usageError(stderr, err.Error())
			}
		}
		identity := item.Identity
		if raw, set := parsed.values["--identity"]; set {
			identity = raw
			if raw == "agent" {
				identity = ""
			}
		}
		binary := item.ServerBinary
		if raw, set := parsed.values["--server-binary"]; set {
			binary = raw
			if raw == "auto" {
				binary = ""
			}
		}
		if _, err := control.UpdateServer(controller.UpdateOptions{
			ID: id, Name: name, Target: target, Port: port, Identity: identity, ServerBinary: binary,
		}); err != nil {
			return usageError(stderr, err.Error())
		}
	}
	if parsed.booleans["--json"] {
		item, _ := control.Store.Server(id)
		if err := writeJSON(stdout, item); err != nil {
			return outputError(stderr, err)
		}
	} else {
		_, _ = fmt.Fprintln(stdout, "Политика сохранена. Выполните fleet install для передачи конфигурации на сервер.")
	}
	return exitOK
}

func runExplain(args []string, stdout, stderr io.Writer) int {
	parsed, err := parse(args, map[string]bool{"--json": false})
	if err != nil {
		return usageError(stderr, err.Error())
	}
	if len(parsed.positionals) > 1 {
		return usageError(stderr, "explain принимает не более одного имени контроля")
	}
	if len(parsed.positionals) == 0 {
		entries := explain.List()
		if parsed.booleans["--json"] {
			if err := writeJSON(stdout, entries); err != nil {
				return outputError(stderr, err)
			}
		} else {
			for _, item := range entries {
				_, _ = fmt.Fprintf(stdout, "%-20s %s\n", item.Control, item.Purpose)
			}
		}
		return exitOK
	}
	entry, ok := explain.Get(parsed.positionals[0])
	if !ok {
		return usageError(stderr, "неизвестный контроль "+parsed.positionals[0])
	}
	if parsed.booleans["--json"] {
		if err := writeJSON(stdout, entry); err != nil {
			return outputError(stderr, err)
		}
	} else {
		_, _ = fmt.Fprintf(stdout, "%s\nНазначение: %s\nРиск: %s\nПроверка: %s\nОткат: %s\n", entry.Control, entry.Purpose, entry.Risk, entry.Check, entry.Rollback)
	}
	return exitOK
}

func parse(args []string, specification map[string]bool) (parsedOptions, error) {
	result := parsedOptions{values: map[string]string{}, booleans: map[string]bool{}, positionals: make([]string, 0)}
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if argument == "--" {
			result.positionals = append(result.positionals, args[index+1:]...)
			break
		}
		if !strings.HasPrefix(argument, "-") {
			result.positionals = append(result.positionals, argument)
			continue
		}
		name, inlineValue, inline := strings.Cut(argument, "=")
		takesValue, known := specification[name]
		if !known {
			return result, fmt.Errorf("неизвестный параметр %s", name)
		}
		if _, duplicated := result.values[name]; duplicated || result.booleans[name] {
			return result, fmt.Errorf("параметр %s задан повторно", name)
		}
		if takesValue {
			value := inlineValue
			if !inline {
				index++
				if index >= len(args) || strings.HasPrefix(args[index], "--") {
					return result, fmt.Errorf("параметру %s требуется значение", name)
				}
				value = args[index]
			}
			if value == "" && name != "--ssh-cidrs" && name != "--tcp-ports" && name != "--udp-ports" && name != "--backup-markers" {
				return result, fmt.Errorf("параметру %s требуется непустое значение", name)
			}
			result.values[name] = value
		} else {
			if inline {
				return result, fmt.Errorf("параметр %s не принимает значение", name)
			}
			result.booleans[name] = true
		}
	}
	return result, nil
}

func oneID(parsed parsedOptions, stderr io.Writer) (string, bool) {
	if len(parsed.positionals) != 1 {
		usageError(stderr, "требуется ровно один ID сервера")
		return "", false
	}
	return parsed.positionals[0], true
}

func optionPort(raw string) (int, error) {
	if raw == "" {
		return 22, nil
	}
	port, err := strconv.Atoi(raw)
	if err != nil || port < 1 || port > 65535 {
		return 0, errors.New("--port должен быть числом 1..65535")
	}
	return port, nil
}

func splitList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return []string{}
	}
	parts := strings.Split(raw, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			result = append(result, part)
		}
	}
	return result
}

func parsePortList(raw string) ([]int, error) {
	parts := splitList(raw)
	ports := make([]int, 0, len(parts))
	for _, part := range parts {
		port, err := strconv.Atoi(part)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("порт %q вне диапазона 1..65535", part)
		}
		ports = append(ports, port)
	}
	return ports, nil
}

func hasAnyValue(parsed parsedOptions, names ...string) bool {
	for _, name := range names {
		if _, exists := parsed.values[name]; exists {
			return true
		}
	}
	return false
}

func writeReport(writer io.Writer, value *report.Report, jsonOutput bool) error {
	if jsonOutput {
		return report.WriteJSON(writer, value)
	}
	return report.WriteText(writer, value)
}

func writeOperation(writer io.Writer, value *controller.OperationResult, jsonOutput bool) error {
	if jsonOutput {
		return writeJSON(writer, value)
	}
	if err := report.WriteText(writer, value.Report); err != nil {
		return err
	}
	if len(value.NewFindings) > 0 {
		_, _ = fmt.Fprintln(writer, "Новые ошибки:", strings.Join(value.NewFindings, ", "))
	}
	_, err := fmt.Fprintln(writer, "История:", value.HistoryPath)
	return err
}

func writeJSON(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func writeSnapshotSummary(writer io.Writer, value inventory.Snapshot) {
	_, _ = fmt.Fprintf(writer, "Snapshot %s (%s, %s)\npackages=%d services=%d accounts=%d listeners=%d managed_files=%d\n",
		value.Host.Hostname, value.Host.Distribution, value.Host.Architecture, len(value.Packages), len(value.Services), len(value.Accounts), len(value.Listeners), len(value.Files))
	for _, warning := range value.Warnings {
		_, _ = fmt.Fprintln(writer, "WARNING", warning)
	}
}

func writeDiff(writer io.Writer, value inventory.Diff) {
	if len(value.Changes) == 0 {
		_, _ = fmt.Fprintln(writer, "Drift не обнаружен.")
		return
	}
	_, _ = fmt.Fprintf(writer, "Drift: %d изменений\n", len(value.Changes))
	for _, change := range value.Changes {
		_, _ = fmt.Fprintf(writer, "%-8s %-13s %-28s %s", strings.ToUpper(change.Kind), change.Category, change.Key, change.Severity)
		if change.Before != "" || change.After != "" {
			_, _ = fmt.Fprintf(writer, "  %s -> %s", change.Before, change.After)
		}
		_, _ = fmt.Fprintln(writer)
	}
}

func writeServers(writer io.Writer, servers []state.ManagedServer) {
	if len(servers) == 0 {
		_, _ = fmt.Fprintln(writer, "Реестр пуст.")
		return
	}
	_, _ = fmt.Fprintln(writer, "ID                   TARGET                         PROFILE       STATUS")
	for _, item := range servers {
		status := item.LastStatus
		if status == "" {
			status = "new"
		}
		if item.BootstrapPending {
			status = "bootstrap"
		}
		_, _ = fmt.Fprintf(writer, "%-20s %-30s %-13s %s\n", item.ID, item.Target, item.Profile, status)
	}
}

func writeHistory(writer io.Writer, entries []state.HistoryEntry) {
	if len(entries) == 0 {
		_, _ = fmt.Fprintln(writer, "История пуста.")
		return
	}
	for _, entry := range entries {
		status := "ok"
		if entry.HasFails {
			status = "fail"
		}
		_, _ = fmt.Fprintf(writer, "%s %-10s %-4s %s\n", entry.Timestamp.Local().Format("2006-01-02 15:04:05"), entry.Action, status, entry.Path)
	}
}

func writeFleetResults(writer io.Writer, results []controller.FleetResult) {
	if len(results) == 0 {
		_, _ = fmt.Fprintln(writer, "Реестр пуст.")
		return
	}
	for _, item := range results {
		if item.Error != "" {
			_, _ = fmt.Fprintf(writer, "%-20s ERROR %s\n", item.Server.ID, item.Error)
			continue
		}
		status := "OK"
		if item.Operation.Report.HasFailures() {
			status = "FAIL"
		}
		_, _ = fmt.Fprintf(writer, "%-20s %-4s fail=%d warn=%d new=%d\n", item.Server.ID, status,
			item.Operation.Report.Summary.Fail, item.Operation.Report.Summary.Warn, len(item.Operation.NewFindings))
	}
}

func usageError(writer io.Writer, message string) int {
	_, _ = fmt.Fprintln(writer, "Ошибка:", message)
	_, _ = fmt.Fprintln(writer, "Используйте bastionctl help для справки.")
	return exitUsage
}

func commandError(writer io.Writer, err error) int {
	_, _ = fmt.Fprintln(writer, "Ошибка:", err)
	return exitUnavailable
}

func outputError(writer io.Writer, err error) int {
	_, _ = fmt.Fprintln(writer, "Ошибка вывода:", err)
	return exitInternal
}

func Help(version string) string {
	return fmt.Sprintf(`bastionctl %s — управление защитой личных серверов

Без аргументов запускается интерактивная консоль администратора.

Основные команды:
  bastionctl console [--state-dir PATH]
  bastionctl fleet list|profiles [--state-dir PATH] [--json]
  bastionctl fleet add ID USER@HOST [--name NAME] [--profile NAME] [--identity PATH]
  bastionctl fleet add ID root@IP --password-bootstrap [--admin-user NAME]
  bastionctl fleet bootstrap ID
  bastionctl fleet configure ID [--profile NAME] [--ssh-cidrs LIST] [--tcp-ports LIST]
  bastionctl fleet install ID [--binary PATH] [--interactive-sudo]
  bastionctl fleet audit|plan ID [--json]
  bastionctl fleet apply ID --yes [--json]
  bastionctl fleet audit-all [--json]
  bastionctl fleet snapshot ID [--baseline] [--json]
  bastionctl fleet diff ID [--json]
  bastionctl fleet baseline ID --yes
  bastionctl fleet history ID [--limit N] [--json]
  bastionctl fleet remove ID --yes
  bastionctl explain [CONTROL] [--json]

Низкоуровневый режим сервера:
  bastionctl server audit|plan [--config PATH] [--json]
  bastionctl server apply --yes [--config PATH] [--json]
  bastionctl server snapshot [--config PATH] [--json]

Прямой admin-режим:
  bastionctl admin doctor [--identity PATH] [--json]
  bastionctl admin audit|plan USER@HOST [--port N] [--identity PATH] [--json]
  bastionctl admin apply USER@HOST --yes [--port N] [--identity PATH] [--json]
  bastionctl admin snapshot USER@HOST [--config PATH] [--json]
  bastionctl admin install USER@HOST --binary PATH --config PATH [--install-sudo] [--interactive-sudo]

Гарантии процесса:
  audit, plan и snapshot ничего не меняют;
  apply требует отдельный plan и явное подтверждение;
  пароль первого входа обрабатывает только OpenSSH и приложение его не хранит;
  после bootstrap SSH использует BatchMode и строгую проверку host key;
  перед включением firewall проверяются ключ, sudo, sshd и текущая SSH-сессия.
`, version)
}
