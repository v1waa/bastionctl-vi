package controller

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"bastionctl/internal/admin"
	"bastionctl/internal/config"
	"bastionctl/internal/inventory"
	"bastionctl/internal/profile"
	"bastionctl/internal/report"
	"bastionctl/internal/state"
)

type Controller struct {
	Version string
	Store   *state.Store
}

type AddOptions struct {
	ID                 string
	Name               string
	Target             string
	Port               int
	Identity           string
	Profile            string
	SSHAllowedCIDRs    []string
	AdditionalTCPPorts []int
	AdditionalUDPPorts []int
	BackupMarkers      []string
	BackupMaxAgeHours  int
	BackupRequired     bool
	ServerBinary       string
	AcceptNewHostKey   bool
	PasswordBootstrap  bool
	BootstrapAdminUser string
}

type UpdateOptions struct {
	ID           string
	Name         string
	Target       string
	Port         int
	Identity     string
	ServerBinary string
}

type OperationResult struct {
	Server      state.ManagedServer `json:"server"`
	Report      *report.Report      `json:"report"`
	NewFindings []string            `json:"new_findings,omitempty"`
	HistoryPath string              `json:"history_path"`
}

type SnapshotResult struct {
	Server          state.ManagedServer `json:"server"`
	Snapshot        inventory.Snapshot  `json:"snapshot"`
	Diff            *inventory.Diff     `json:"diff,omitempty"`
	BaselineCreated bool                `json:"baseline_created"`
}

type FleetResult struct {
	Server    state.ManagedServer `json:"server"`
	Operation *OperationResult    `json:"operation,omitempty"`
	Error     string              `json:"error,omitempty"`
}

func New(version, root string) (*Controller, error) {
	store, err := state.Open(root)
	if err != nil {
		return nil, err
	}
	return &Controller{Version: version, Store: store}, nil
}

func (c *Controller) List() ([]state.ManagedServer, error) {
	registry, err := c.Store.LoadRegistry()
	if err != nil {
		return nil, err
	}
	servers := append([]state.ManagedServer(nil), registry.Servers...)
	sort.Slice(servers, func(i, j int) bool { return servers[i].ID < servers[j].ID })
	return servers, nil
}

func (c *Controller) AddServer(options AddOptions) (state.ManagedServer, error) {
	options.ID = strings.TrimSpace(strings.ToLower(options.ID))
	if err := state.ValidateID(options.ID); err != nil {
		return state.ManagedServer{}, err
	}
	if err := admin.ValidateTarget(options.Target); err != nil {
		return state.ManagedServer{}, err
	}
	bootstrapTarget := ""
	managedTarget := options.Target
	if options.PasswordBootstrap {
		bootstrapTarget = options.Target
		loginUser, host := splitTarget(options.Target)
		adminUser := strings.TrimSpace(options.BootstrapAdminUser)
		if loginUser == "root" {
			if adminUser == "" {
				adminUser = "bastion"
			}
			if err := admin.ValidateBootstrapUsername(adminUser); err != nil {
				return state.ManagedServer{}, err
			}
			managedTarget = adminUser + "@" + host
			if err := admin.ValidateTarget(managedTarget); err != nil {
				return state.ManagedServer{}, fmt.Errorf("непривилегированный администратор: %w", err)
			}
		} else if adminUser != "" && adminUser != loginUser {
			return state.ManagedServer{}, errors.New("другого администратора можно создать только при первом входе от root")
		}
	} else {
		managedUser, _ := splitTarget(managedTarget)
		if managedUser == "root" {
			return state.ManagedServer{}, errors.New("постоянное управление от root запрещено; используйте --password-bootstrap для создания непривилегированного администратора")
		}
		if strings.TrimSpace(options.BootstrapAdminUser) != "" {
			return state.ManagedServer{}, errors.New("--admin-user используется только вместе с password bootstrap")
		}
	}
	if options.Port == 0 {
		options.Port = 22
	}
	if options.Port < 1 || options.Port > 65535 {
		return state.ManagedServer{}, errors.New("SSH-порт должен быть в диапазоне 1..65535")
	}
	if options.Name == "" {
		options.Name = options.ID
	}
	if strings.TrimSpace(options.Name) == "" || len(options.Name) > 100 {
		return state.ManagedServer{}, errors.New("имя сервера обязательно и не должно превышать 100 символов")
	}
	if options.Profile == "" {
		options.Profile = "minimal"
	}
	if _, ok := profile.Get(options.Profile); !ok {
		return state.ManagedServer{}, fmt.Errorf("неизвестный профиль %q", options.Profile)
	}
	options.Identity = admin.ExpandIdentity(strings.TrimSpace(options.Identity))
	if options.Identity != "" {
		info, err := os.Lstat(options.Identity)
		if err != nil {
			return state.ManagedServer{}, fmt.Errorf("закрытый ключ недоступен: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return state.ManagedServer{}, errors.New("закрытый ключ должен быть обычным файлом без symlink")
		}
	}
	registry, err := c.Store.LoadRegistry()
	if err != nil {
		return state.ManagedServer{}, err
	}
	for _, existing := range registry.Servers {
		if existing.ID == options.ID {
			return state.ManagedServer{}, fmt.Errorf("сервер с ID %q уже существует", options.ID)
		}
	}
	if options.PasswordBootstrap {
		if options.Identity == "" {
			identityPath, pathErr := c.Store.ServerIdentityPath(options.ID)
			if pathErr != nil {
				return state.ManagedServer{}, pathErr
			}
			if keyErr := admin.GenerateIdentity(context.Background(), identityPath, "bastionctl:"+options.ID); keyErr != nil {
				return state.ManagedServer{}, keyErr
			}
			options.Identity = identityPath
		} else if _, keyErr := admin.ReadPublicKey(options.Identity + ".pub"); keyErr != nil {
			return state.ManagedServer{}, fmt.Errorf("для bootstrap нужен соседний файл .pub: %w", keyErr)
		}
		options.AcceptNewHostKey = true
	}

	cfg, err := profile.Apply(options.Profile, config.Defaults())
	if err != nil {
		return state.ManagedServer{}, err
	}
	cfg.Server.AdminUser = managedTarget[:strings.Index(managedTarget, "@")]
	cfg.Server.SSHAllowedCIDRs = cleanStrings(options.SSHAllowedCIDRs)
	cfg.Server.AllowedTCPPorts = append(cfg.Server.AllowedTCPPorts, options.AdditionalTCPPorts...)
	cfg.Server.AllowedUDPPorts = append(cfg.Server.AllowedUDPPorts, options.AdditionalUDPPorts...)
	cfg.Server.BackupMarkers = cleanStrings(options.BackupMarkers)
	if options.BackupMaxAgeHours > 0 {
		cfg.Server.BackupMaxAgeHours = options.BackupMaxAgeHours
	}
	cfg.Server.BackupRequired = options.BackupRequired
	cfg.Admin.StrictHostKeyChecking = !options.AcceptNewHostKey
	data, err := config.Render(cfg)
	if err != nil {
		return state.ManagedServer{}, err
	}
	configPath, err := c.Store.SaveServerConfig(options.ID, data)
	if err != nil {
		return state.ManagedServer{}, err
	}
	item := state.ManagedServer{
		ID: options.ID, Name: options.Name, Target: managedTarget, Port: options.Port,
		Identity: options.Identity, Profile: options.Profile, ConfigPath: configPath,
		ServerBinary:    admin.ExpandIdentity(strings.TrimSpace(options.ServerBinary)),
		BootstrapTarget: bootstrapTarget, BootstrapPending: options.PasswordBootstrap,
		InteractiveSudo: options.PasswordBootstrap,
	}
	if err := c.Store.AddServer(item); err != nil {
		return state.ManagedServer{}, err
	}
	return c.Store.Server(item.ID)
}

func (c *Controller) RemoveServer(id string) error {
	return c.Store.RemoveServer(id)
}

func (c *Controller) UpdateServer(options UpdateOptions) (state.ManagedServer, error) {
	item, err := c.Store.Server(options.ID)
	if err != nil {
		return state.ManagedServer{}, err
	}
	if strings.TrimSpace(options.Name) == "" || len(options.Name) > 100 {
		return state.ManagedServer{}, errors.New("имя сервера обязательно и не должно превышать 100 символов")
	}
	if err := admin.ValidateTarget(options.Target); err != nil {
		return state.ManagedServer{}, err
	}
	if options.Port < 1 || options.Port > 65535 {
		return state.ManagedServer{}, errors.New("SSH-порт должен быть в диапазоне 1..65535")
	}
	options.Identity = admin.ExpandIdentity(strings.TrimSpace(options.Identity))
	if item.BootstrapPending && (options.Target != item.Target || options.Port != item.Port || options.Identity != item.Identity) {
		return state.ManagedServer{}, errors.New("сначала завершите первичный вход; затем меняйте SSH-цель, порт или ключ")
	}
	if options.Identity != "" {
		info, err := os.Lstat(options.Identity)
		if err != nil {
			return state.ManagedServer{}, fmt.Errorf("закрытый ключ недоступен: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return state.ManagedServer{}, errors.New("закрытый ключ должен быть обычным файлом без symlink")
		}
	}
	cfg, err := config.Load(item.ConfigPath)
	if err != nil {
		return state.ManagedServer{}, err
	}
	cfg.Server.AdminUser = options.Target[:strings.Index(options.Target, "@")]
	data, err := config.Render(cfg)
	if err != nil {
		return state.ManagedServer{}, err
	}
	configPath, err := c.Store.SaveServerConfig(item.ID, data)
	if err != nil {
		return state.ManagedServer{}, err
	}
	item.Name = options.Name
	item.Target = options.Target
	item.Port = options.Port
	item.Identity = options.Identity
	item.ServerBinary = admin.ExpandIdentity(strings.TrimSpace(options.ServerBinary))
	item.ConfigPath = configPath
	if err := c.Store.UpdateServer(item); err != nil {
		return state.ManagedServer{}, err
	}
	return c.Store.Server(item.ID)
}

func (c *Controller) Config(id string) (config.Config, error) {
	item, err := c.Store.Server(id)
	if err != nil {
		return config.Config{}, err
	}
	return config.Load(item.ConfigPath)
}

func (c *Controller) SaveConfig(id string, cfg config.Config) error {
	item, err := c.Store.Server(id)
	if err != nil {
		return err
	}
	if _, ok := profile.Get(cfg.Server.Profile); !ok {
		return fmt.Errorf("неизвестный профиль %q", cfg.Server.Profile)
	}
	if item.BootstrapPending && cfg.Admin.StrictHostKeyChecking {
		return errors.New("до первичного входа host-key policy должна оставаться в интерактивном bootstrap-режиме")
	}
	data, err := config.Render(cfg)
	if err != nil {
		return err
	}
	path, err := c.Store.SaveServerConfig(id, data)
	if err != nil {
		return err
	}
	item.ConfigPath = path
	item.Profile = cfg.Server.Profile
	return c.Store.UpdateServer(item)
}

func (c *Controller) ApplyProfile(id, name string) error {
	cfg, err := c.Config(id)
	if err != nil {
		return err
	}
	cfg, err = profile.Apply(name, cfg)
	if err != nil {
		return err
	}
	return c.SaveConfig(id, cfg)
}

func (c *Controller) RunAction(ctx context.Context, id, action string, yes bool) (*OperationResult, error) {
	if action != "audit" && action != "plan" && action != "apply" {
		return nil, errors.New("действие должно быть audit, plan или apply")
	}
	if action == "apply" && !yes {
		return nil, errors.New("apply требует явного подтверждения")
	}
	item, err := c.Store.Server(id)
	if err != nil {
		return nil, err
	}
	if item.BootstrapPending {
		return nil, errors.New("сначала выполните первичный SSH-вход: fleet bootstrap " + item.ID)
	}
	cfg, err := config.Load(item.ConfigPath)
	if err != nil {
		return nil, err
	}
	previous, previousErr := c.Store.LatestReport(id, action)
	if previousErr != nil && !os.IsNotExist(previousErr) {
		return nil, previousErr
	}
	r := admin.Run(ctx, cfg.Admin, c.Version, admin.Options{
		Action: action, Target: item.Target, Port: item.Port, Identity: item.Identity, Yes: yes,
	})
	newFindings := findNewFailures(previous, r)
	if !transportFailed(r) {
		promoted, promoteErr := c.promoteStrictHostKey(id, &cfg)
		if promoteErr != nil {
			return nil, promoteErr
		}
		if promoted {
			r.Warnings = append(r.Warnings, "первое соединение успешно: дальнейшая проверка SSH host key переключена в строгий режим")
		}
	}
	historyPath, err := c.Store.SaveReport(id, r)
	if err != nil {
		return nil, err
	}
	item.LastAction = action
	if r.HasFailures() {
		item.LastStatus = "fail"
	} else {
		item.LastStatus = "ok"
	}
	if !transportFailed(r) {
		item.LastSeenAt = time.Now().UTC()
	}
	if err := c.Store.UpdateServer(item); err != nil {
		return nil, err
	}
	item, _ = c.Store.Server(id)
	return &OperationResult{Server: item, Report: r, NewFindings: newFindings, HistoryPath: historyPath}, nil
}

func (c *Controller) AuditAll(ctx context.Context) ([]FleetResult, error) {
	servers, err := c.List()
	if err != nil {
		return nil, err
	}
	results := make([]FleetResult, 0, len(servers))
	for _, item := range servers {
		operation, runErr := c.RunAction(ctx, item.ID, "audit", false)
		entry := FleetResult{Server: item, Operation: operation}
		if runErr != nil {
			entry.Error = runErr.Error()
		}
		results = append(results, entry)
		if ctx.Err() != nil {
			break
		}
	}
	return results, nil
}

func (c *Controller) BootstrapAccess(ctx context.Context, id string, input io.Reader, output io.Writer) (state.ManagedServer, error) {
	item, err := c.Store.Server(id)
	if err != nil {
		return state.ManagedServer{}, err
	}
	if !item.BootstrapPending {
		return state.ManagedServer{}, errors.New("первичный SSH-вход для этого сервера уже завершён")
	}
	cfg, err := config.Load(item.ConfigPath)
	if err != nil {
		return state.ManagedServer{}, err
	}
	if err := admin.BootstrapKey(ctx, cfg.Admin, admin.BootstrapOptions{
		Login: admin.Options{
			Target: item.BootstrapTarget, Port: item.Port, Identity: item.Identity,
		},
		ManagedTarget: item.Target,
		PublicKeyPath: item.Identity + ".pub",
		Input:         input,
		Output:        output,
	}); err != nil {
		item.LastAction = "bootstrap"
		item.LastStatus = "fail"
		_ = c.Store.UpdateServer(item)
		return state.ManagedServer{}, err
	}
	if _, err := c.promoteStrictHostKey(id, &cfg); err != nil {
		return state.ManagedServer{}, err
	}
	item.BootstrapPending = false
	item.BootstrapTarget = ""
	item.LastAction = "bootstrap"
	item.LastStatus = "ok"
	item.LastSeenAt = time.Now().UTC()
	if err := c.Store.UpdateServer(item); err != nil {
		return state.ManagedServer{}, err
	}
	return c.Store.Server(id)
}

func (c *Controller) Install(ctx context.Context, id, binaryPath string, input io.Reader, output io.Writer, interactiveSudo bool) (*OperationResult, error) {
	item, err := c.Store.Server(id)
	if err != nil {
		return nil, err
	}
	if item.BootstrapPending {
		if _, err := c.BootstrapAccess(ctx, id, input, output); err != nil {
			return nil, fmt.Errorf("первичный SSH-вход: %w", err)
		}
		item, err = c.Store.Server(id)
		if err != nil {
			return nil, err
		}
	}
	cfg, err := config.Load(item.ConfigPath)
	if err != nil {
		return nil, err
	}
	connection := admin.Options{Target: item.Target, Port: item.Port, Identity: item.Identity}
	architecture, err := admin.DetectArchitecture(ctx, cfg.Admin, connection)
	if err != nil {
		return nil, fmt.Errorf("определить архитектуру сервера: %w", err)
	}
	selected, err := c.resolveServerBinary(item, binaryPath, architecture)
	if err != nil {
		return nil, err
	}
	r := admin.Install(ctx, cfg.Admin, c.Version, admin.InstallOptions{
		Connection: connection, BinaryPath: selected, ConfigPath: item.ConfigPath,
		InstallSudo: true, ExpectedArch: architecture,
		InteractiveSudo: interactiveSudo || item.InteractiveSudo, Input: input, Output: output,
	})
	if !r.HasFailures() {
		promoted, promoteErr := c.promoteStrictHostKey(id, &cfg)
		if promoteErr != nil {
			return nil, promoteErr
		}
		if promoted {
			r.Warnings = append(r.Warnings, "первое соединение успешно: дальнейшая проверка SSH host key переключена в строгий режим")
		}
	}
	historyPath, err := c.Store.SaveReport(id, r)
	if err != nil {
		return nil, err
	}
	item.ServerBinary = selected
	item.LastAction = "install"
	if r.HasFailures() {
		item.LastStatus = "fail"
	} else {
		item.LastStatus = "ok"
		item.LastSeenAt = time.Now().UTC()
	}
	if err := c.Store.UpdateServer(item); err != nil {
		return nil, err
	}
	item, _ = c.Store.Server(id)
	return &OperationResult{Server: item, Report: r, HistoryPath: historyPath}, nil
}

func (c *Controller) CaptureSnapshot(ctx context.Context, id string, forceBaseline bool) (*SnapshotResult, error) {
	item, err := c.Store.Server(id)
	if err != nil {
		return nil, err
	}
	if item.BootstrapPending {
		return nil, errors.New("сначала выполните первичный SSH-вход: fleet bootstrap " + item.ID)
	}
	cfg, err := config.Load(item.ConfigPath)
	if err != nil {
		return nil, err
	}
	baseline, baselineErr := c.Store.LoadSnapshot(id, "baseline")
	if baselineErr != nil && !os.IsNotExist(baselineErr) {
		return nil, baselineErr
	}
	snapshot, err := admin.CaptureSnapshot(ctx, cfg.Admin, c.Version, admin.Options{
		Target: item.Target, Port: item.Port, Identity: item.Identity,
	})
	if err != nil {
		return nil, err
	}
	if promoted, promoteErr := c.promoteStrictHostKey(id, &cfg); promoteErr != nil {
		return nil, promoteErr
	} else if promoted {
		snapshot.Warnings = append(snapshot.Warnings, "первое соединение успешно: дальнейшая проверка SSH host key переключена в строгий режим")
	}
	createBaseline := forceBaseline || os.IsNotExist(baselineErr)
	if err := c.Store.SaveSnapshot(id, snapshot, createBaseline); err != nil {
		return nil, err
	}
	result := &SnapshotResult{Server: item, Snapshot: snapshot, BaselineCreated: createBaseline}
	if baselineErr == nil && !forceBaseline {
		diff, compareErr := inventory.Compare(baseline, snapshot)
		if compareErr != nil {
			return nil, compareErr
		}
		result.Diff = &diff
	}
	item.LastAction = "snapshot"
	item.LastStatus = "ok"
	item.LastSeenAt = time.Now().UTC()
	if result.Diff != nil && len(result.Diff.Changes) > 0 {
		item.LastStatus = "drift"
	}
	if err := c.Store.UpdateServer(item); err != nil {
		return nil, err
	}
	result.Server, _ = c.Store.Server(id)
	return result, nil
}

func (c *Controller) Diff(id string) (inventory.Diff, error) {
	baseline, err := c.Store.LoadSnapshot(id, "baseline")
	if err != nil {
		return inventory.Diff{}, err
	}
	latest, err := c.Store.LoadSnapshot(id, "latest")
	if err != nil {
		return inventory.Diff{}, err
	}
	return inventory.Compare(baseline, latest)
}

func (c *Controller) SetLatestAsBaseline(id string) error {
	latest, err := c.Store.LoadSnapshot(id, "latest")
	if err != nil {
		return err
	}
	return c.Store.SaveSnapshot(id, latest, true)
}

func (c *Controller) resolveServerBinary(item state.ManagedServer, requested, architecture string) (string, error) {
	candidates := make([]string, 0, 8)
	appendCandidate := func(path string) {
		path = admin.ExpandIdentity(strings.TrimSpace(path))
		if path == "" {
			return
		}
		for _, existing := range candidates {
			if existing == path {
				return
			}
		}
		candidates = append(candidates, path)
	}
	appendCandidate(requested)
	appendCandidate(item.ServerBinary)
	executable, executableErr := os.Executable()
	if executableErr == nil {
		executable, _ = filepath.Abs(executable)
		directory := filepath.Dir(executable)
		appendCandidate(filepath.Join(directory, "bastionctl-linux-"+architecture))
		appendCandidate(filepath.Join(directory, "dist", "bastionctl-linux-"+architecture))
		if runtime.GOOS == "linux" && runtime.GOARCH == architecture {
			appendCandidate(executable)
		}
	}
	if workingDirectory, err := os.Getwd(); err == nil {
		appendCandidate(filepath.Join(workingDirectory, "dist", "bastionctl-linux-"+architecture))
		appendCandidate(filepath.Join(workingDirectory, "bastionctl-linux-"+architecture))
	}
	for _, candidate := range candidates {
		absolute, err := filepath.Abs(candidate)
		if err != nil {
			continue
		}
		candidateArch, err := admin.ELFArchitecture(absolute)
		if err == nil && candidateArch == architecture {
			return absolute, nil
		}
	}
	return "", fmt.Errorf("не найдена Linux-сборка %s; укажите путь к bastionctl-linux-%s", architecture, architecture)
}

func cleanStrings(values []string) []string {
	result := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func splitTarget(target string) (string, string) {
	separator := strings.LastIndex(target, "@")
	return target[:separator], target[separator+1:]
}

func findNewFailures(previous, current *report.Report) []string {
	known := map[string]struct{}{}
	if previous != nil {
		for _, item := range previous.Results {
			if item.Status == report.Fail {
				known[item.Control] = struct{}{}
			}
		}
	}
	result := make([]string, 0)
	for _, item := range current.Results {
		if item.Status != report.Fail {
			continue
		}
		if _, exists := known[item.Control]; !exists {
			result = append(result, item.Control)
		}
	}
	sort.Strings(result)
	return result
}

func transportFailed(value *report.Report) bool {
	for _, item := range value.Results {
		if item.Status != report.Fail {
			continue
		}
		switch item.Control {
		case "target", "port", "connection", "remote-execution", "remote-report":
			return true
		}
	}
	return false
}

func (c *Controller) promoteStrictHostKey(id string, cfg *config.Config) (bool, error) {
	if cfg.Admin.StrictHostKeyChecking {
		return false, nil
	}
	cfg.Admin.StrictHostKeyChecking = true
	data, err := config.Render(*cfg)
	if err != nil {
		return false, err
	}
	if _, err := c.Store.SaveServerConfig(id, data); err != nil {
		return false, err
	}
	return true, nil
}
