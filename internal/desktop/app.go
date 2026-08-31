package desktop

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"bastionctl/internal/admin"
	"bastionctl/internal/controller"
	"bastionctl/internal/inventory"
	"bastionctl/internal/profile"
	"bastionctl/internal/report"
	"bastionctl/internal/serverpayload"
	"bastionctl/internal/state"
	"bastionctl/internal/terminal"
	"bastionctl/internal/workload"
)

type EventSink func(name string, payload any)

type App struct {
	version    string
	controller *controller.Controller
	terminal   *terminal.Manager
	emit       EventSink

	mu     sync.RWMutex
	ctx    context.Context
	cancel context.CancelFunc
}

type InitialState struct {
	Version   string       `json:"version"`
	Platform  string       `json:"platform"`
	StateRoot string       `json:"state_root"`
	Servers   []ServerView `json:"servers"`
	Profiles  []string     `json:"profiles"`
}

type ServerView struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	Target           string    `json:"target"`
	Port             int       `json:"port"`
	Identity         string    `json:"identity,omitempty"`
	Profile          string    `json:"profile"`
	BootstrapTarget  string    `json:"bootstrap_target,omitempty"`
	BootstrapPending bool      `json:"bootstrap_pending"`
	HostKeyTrusted   bool      `json:"host_key_trusted"`
	LastSeenAt       time.Time `json:"last_seen_at,omitempty"`
	LastAction       string    `json:"last_action,omitempty"`
	LastStatus       string    `json:"last_status,omitempty"`
}

type AddServerRequest struct {
	ID                 string   `json:"id"`
	Name               string   `json:"name"`
	Target             string   `json:"target"`
	Port               int      `json:"port"`
	Identity           string   `json:"identity"`
	Profile            string   `json:"profile"`
	SSHAllowedCIDRs    []string `json:"ssh_allowed_cidrs"`
	PasswordBootstrap  bool     `json:"password_bootstrap"`
	BootstrapAdminUser string   `json:"bootstrap_admin_user"`
}

type UpdateServerRequest struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Target   string `json:"target"`
	Port     int    `json:"port"`
	Identity string `json:"identity"`
}

type HostKeyView struct {
	terminal.HostKeyInfo
	Changed bool `json:"changed"`
}

type TerminalRequest struct {
	ServerID   string `json:"server_id"`
	Password   string `json:"password"`
	Passphrase string `json:"passphrase"`
	Columns    int    `json:"columns"`
	Rows       int    `json:"rows"`
}

type BootstrapRequest struct {
	ServerID string `json:"server_id"`
	Password string `json:"password"`
	Columns  int    `json:"columns"`
	Rows     int    `json:"rows"`
}

type InstallRequest struct {
	ServerID     string `json:"server_id"`
	Confirmation string `json:"confirmation"`
	Passphrase   string `json:"passphrase"`
	Columns      int    `json:"columns"`
	Rows         int    `json:"rows"`
}

type InstallPreviewRequest struct {
	ServerID   string `json:"server_id"`
	Passphrase string `json:"passphrase"`
}

type InstallPreviewView struct {
	UbuntuVersion    string `json:"ubuntu_version"`
	Architecture     string `json:"architecture"`
	PayloadName      string `json:"payload_name"`
	PayloadSize      int64  `json:"payload_size"`
	PayloadSHA256    string `json:"payload_sha256"`
	RemoteExecutable string `json:"remote_executable"`
	RemoteConfig     string `json:"remote_config"`
}

type SecurityActionRequest struct {
	ServerID     string `json:"server_id"`
	Action       string `json:"action"`
	Confirmation string `json:"confirmation"`
	Passphrase   string `json:"passphrase"`
}

type UserRequest struct {
	ServerID   string `json:"server_id"`
	Username   string `json:"username"`
	PublicKey  string `json:"public_key"`
	GrantSudo  bool   `json:"grant_sudo"`
	Passphrase string `json:"passphrase"`
}

type SecuritySettings struct {
	Profile                string `json:"profile"`
	ManageSSH              bool   `json:"manage_ssh"`
	ManageFirewall         bool   `json:"manage_firewall"`
	ManageFail2ban         bool   `json:"manage_fail2ban"`
	ManageAutomaticUpdates bool   `json:"manage_automatic_updates"`
	ManageAuditd           bool   `json:"manage_auditd"`
	ManageAppArmor         bool   `json:"manage_apparmor"`
	ManageTimeSync         bool   `json:"manage_time_sync"`
	PasswordAuthentication bool   `json:"password_authentication"`
	PermitRootLogin        bool   `json:"permit_root_login"`
	SSHAllowedCIDRs        string `json:"ssh_allowed_cidrs"`
	AllowedTCPPorts        string `json:"allowed_tcp_ports"`
	AllowedUDPPorts        string `json:"allowed_udp_ports"`
	AutomaticReboot        bool   `json:"automatic_reboot"`
	AutomaticRebootTime    string `json:"automatic_reboot_time"`
	BackupMarkers          string `json:"backup_markers"`
	BackupMaxAgeHours      int    `json:"backup_max_age_hours"`
	BackupRequired         bool   `json:"backup_required"`
}

type XHTTPRequest struct {
	ServerID  string `json:"server_id"`
	Domain    string `json:"domain"`
	Email     string `json:"email"`
	ServerIP  string `json:"server_ip"`
	PanelPort int    `json:"panel_port"`
}

type SnapshotRequest struct {
	ServerID      string `json:"server_id"`
	ForceBaseline bool   `json:"force_baseline"`
	Passphrase    string `json:"passphrase"`
}

type XHTTPActionRequest struct {
	ServerID     string `json:"server_id"`
	Action       string `json:"action"`
	Confirmation string `json:"confirmation"`
	Passphrase   string `json:"passphrase"`
}

type GuideStep struct {
	Title   string   `json:"title"`
	Details []string `json:"details"`
}

type XHTTPView struct {
	Configured bool                 `json:"configured"`
	Config     workload.XHTTPConfig `json:"config"`
	Guide      []GuideStep          `json:"guide"`
}

func New(version, root string, sink EventSink) (*App, error) {
	control, err := controller.New(version, root)
	if err != nil {
		return nil, err
	}
	if sink == nil {
		sink = func(string, any) {}
	}
	app := &App{version: version, controller: control, emit: sink}
	app.ctx, app.cancel = context.WithCancel(context.Background())
	app.terminal = terminal.NewManager(func(event terminal.Event) {
		app.emit("terminal:event", event)
	})
	return app, nil
}

func (a *App) Close() {
	a.mu.Lock()
	if a.cancel != nil {
		a.cancel()
	}
	a.mu.Unlock()
	_ = a.terminal.Close()
}

func (a *App) InitialState() (InitialState, error) {
	servers, err := a.controller.List()
	if err != nil {
		return InitialState{}, err
	}
	views := make([]ServerView, 0, len(servers))
	for _, item := range servers {
		views = append(views, a.serverView(item))
	}
	profiles := profile.Names()
	sort.Strings(profiles)
	return InitialState{
		Version: a.version, Platform: runtime.GOOS + "/" + runtime.GOARCH,
		StateRoot: a.controller.Store.Root(), Servers: views, Profiles: profiles,
	}, nil
}

func (a *App) AddServer(request AddServerRequest) (ServerView, error) {
	item, err := a.controller.AddServer(controller.AddOptions{
		ID: request.ID, Name: request.Name, Target: request.Target, Port: request.Port,
		Identity: request.Identity, Profile: request.Profile, SSHAllowedCIDRs: request.SSHAllowedCIDRs,
		ServerBinary: "", PasswordBootstrap: request.PasswordBootstrap,
		BootstrapAdminUser: request.BootstrapAdminUser,
	})
	if err != nil {
		return ServerView{}, err
	}
	return a.serverView(item), nil
}

func (a *App) UpdateServer(request UpdateServerRequest) (ServerView, error) {
	item, err := a.controller.UpdateServer(controller.UpdateOptions{
		ID: request.ID, Name: request.Name, Target: request.Target, Port: request.Port,
		Identity: request.Identity, ServerBinary: "",
	})
	if err != nil {
		return ServerView{}, err
	}
	return a.serverView(item), nil
}

func (a *App) RemoveServer(id, confirmation string) error {
	if confirmation != "REMOVE "+id {
		return errors.New("для удаления записи введите REMOVE " + id)
	}
	return a.controller.RemoveServer(id)
}

func (a *App) ProbeHostKey(id string) (HostKeyView, error) {
	item, path, err := a.connectionDetails(id)
	if err != nil {
		return HostKeyView{}, err
	}
	ctx, cancel := context.WithTimeout(a.context(), 15*time.Second)
	defer cancel()
	info, key, err := terminal.ProbeHostKey(ctx, probeTarget(item), item.Port, 10*time.Second)
	if err != nil {
		return HostKeyView{}, err
	}
	view := HostKeyView{HostKeyInfo: info}
	if terminal.HasPinnedHostKey(path) {
		callback, callbackErr := terminal.PinnedHostKeyCallback(path)
		if callbackErr != nil {
			return HostKeyView{}, callbackErr
		}
		if callbackErr = callback(info.Address, stringAddress(info.Address), key); callbackErr == nil {
			view.Trusted = true
		} else {
			view.Changed = true
		}
	}
	return view, nil
}

func (a *App) TrustHostKey(id, observed, confirmation string) (HostKeyView, error) {
	item, path, err := a.connectionDetails(id)
	if err != nil {
		return HostKeyView{}, err
	}
	ctx, cancel := context.WithTimeout(a.context(), 15*time.Second)
	defer cancel()
	info, err := terminal.TrustHostKey(ctx, probeTarget(item), item.Port, path, observed, confirmation, 10*time.Second)
	return HostKeyView{HostKeyInfo: info}, err
}

func (a *App) ReplaceHostKey(id, observed, confirmation string) (HostKeyView, error) {
	item, path, err := a.connectionDetails(id)
	if err != nil {
		return HostKeyView{}, err
	}
	ctx, cancel := context.WithTimeout(a.context(), 15*time.Second)
	defer cancel()
	info, err := terminal.ReplaceHostKey(ctx, probeTarget(item), item.Port, path, observed, confirmation, 10*time.Second)
	return HostKeyView{HostKeyInfo: info}, err
}

func (a *App) StartTerminal(request TerminalRequest) (string, error) {
	item, path, err := a.connectionDetails(request.ServerID)
	if err != nil {
		return "", err
	}
	if item.BootstrapPending {
		return "", errors.New("сначала завершите первичный вход по паролю")
	}
	if !terminal.HasPinnedHostKey(path) {
		return "", errors.New("сначала сверьте и закрепите SSH fingerprint")
	}
	handle, err := a.terminal.StartShell(a.context(), terminal.Connection{
		ServerID: item.ID, Target: item.Target, Port: item.Port, Identity: item.Identity,
		KnownHosts: path, ConnectTimeout: 10 * time.Second,
	}, terminal.Credentials{Password: request.Password, Passphrase: request.Passphrase}, request.Columns, request.Rows)
	if err != nil {
		return "", err
	}
	return handle.ID, nil
}

func (a *App) StartBootstrap(request BootstrapRequest) (string, error) {
	item, path, err := a.connectionDetails(request.ServerID)
	if err != nil {
		return "", err
	}
	if !item.BootstrapPending || item.BootstrapTarget == "" {
		return "", errors.New("первичный вход для сервера не ожидается")
	}
	if request.Password == "" {
		return "", errors.New("введите одноразовый пароль первичного SSH-входа")
	}
	if !terminal.HasPinnedHostKey(path) {
		return "", errors.New("сначала сверьте и закрепите SSH fingerprint")
	}
	command, err := admin.BootstrapCommand(item.BootstrapTarget, item.Target, item.Identity+".pub")
	if err != nil {
		return "", err
	}
	handle, err := a.terminal.StartCommand(a.context(), terminal.Connection{
		ServerID: item.ID, Target: item.BootstrapTarget, Port: item.Port,
		KnownHosts: path, ConnectTimeout: 10 * time.Second,
	}, terminal.Credentials{Password: request.Password}, request.Columns, request.Rows, command)
	request.Password = ""
	if err != nil {
		return "", err
	}
	go a.finishBootstrap(item.ID, handle)
	return handle.ID, nil
}

func (a *App) TerminalInput(sessionID, data string) error {
	return a.terminal.Write(sessionID, data)
}

func (a *App) TerminalResize(sessionID string, columns, rows int) error {
	return a.terminal.Resize(sessionID, columns, rows)
}

func (a *App) StopTerminal(sessionID string) error {
	return a.terminal.Stop(sessionID)
}

func (a *App) RunSecurityAction(request SecurityActionRequest) (*controller.OperationResult, error) {
	action := strings.TrimSpace(request.Action)
	switch action {
	case "audit", "plan", "reset-plan":
	case "apply":
		if request.Confirmation != "APPLY "+request.ServerID {
			return nil, errors.New("для применения введите APPLY " + request.ServerID)
		}
	case "reset":
		if request.Confirmation != "RESET "+request.ServerID {
			return nil, errors.New("для сброса введите RESET " + request.ServerID)
		}
	default:
		return nil, errors.New("неподдерживаемое действие безопасности")
	}
	ctx, cancel := context.WithTimeout(a.context(), 20*time.Minute)
	defer cancel()
	result, err := a.controller.RunActionEmbedded(ctx, request.ServerID, action, action == "apply" || action == "reset", request.Passphrase)
	request.Passphrase = ""
	return result, err
}

func (a *App) InstallPreview(request InstallPreviewRequest) (InstallPreviewView, error) {
	item, path, err := a.connectionDetails(request.ServerID)
	if err != nil {
		return InstallPreviewView{}, err
	}
	if item.BootstrapPending {
		return InstallPreviewView{}, errors.New("сначала завершите первичный вход по паролю")
	}
	if !terminal.HasPinnedHostKey(path) {
		return InstallPreviewView{}, errors.New("сначала сверьте и закрепите SSH fingerprint")
	}
	cfg, err := a.controller.Config(item.ID)
	if err != nil {
		return InstallPreviewView{}, err
	}
	ctx, cancel := context.WithTimeout(a.context(), 45*time.Second)
	defer cancel()
	preview, _, _, err := a.inspectInstallTarget(ctx, item, path, request.Passphrase, cfg.Admin.RemoteExecutable, cfg.Admin.RemoteConfig)
	request.Passphrase = ""
	return preview, err
}

func (a *App) StartInstall(request InstallRequest) (string, error) {
	if request.Confirmation != "INSTALL "+request.ServerID {
		return "", errors.New("для установки введите INSTALL " + request.ServerID)
	}
	item, path, err := a.connectionDetails(request.ServerID)
	if err != nil {
		return "", err
	}
	if item.BootstrapPending {
		return "", errors.New("сначала завершите первичный вход по паролю")
	}
	if !terminal.HasPinnedHostKey(path) {
		return "", errors.New("сначала сверьте и закрепите SSH fingerprint")
	}
	cfg, err := a.controller.Config(item.ID)
	if err != nil {
		return "", err
	}
	credentials := terminal.Credentials{Passphrase: request.Passphrase}
	prepareCtx, cancel := context.WithTimeout(a.context(), 8*time.Minute)
	defer cancel()
	preview, payload, connection, err := a.inspectInstallTarget(prepareCtx, item, path, request.Passphrase, cfg.Admin.RemoteExecutable, cfg.Admin.RemoteConfig)
	if err != nil {
		return "", err
	}
	prepared, err := admin.PrepareInstallPayload(cfg.Admin, item.Target, payload.Name, payload.Data, item.ConfigPath, preview.Architecture, true, true)
	if err != nil {
		return "", err
	}
	started := false
	defer func() {
		if !started {
			prepared.Close()
		}
	}()
	for _, upload := range prepared.Uploads {
		var uploadErr error
		if len(upload.Data) != 0 {
			uploadErr = terminal.UploadBytes(prepareCtx, connection, credentials, upload.Data, upload.Remote, 100<<20)
		} else {
			uploadErr = terminal.UploadFile(prepareCtx, connection, credentials, upload.Local, upload.Remote, 100<<20)
		}
		if uploadErr != nil {
			a.cleanupPreparedInstall(prepareCtx, connection, credentials, prepared)
			return "", uploadErr
		}
	}
	handle, err := a.terminal.StartCommand(a.context(), connection, credentials, request.Columns, request.Rows, prepared.Command)
	if err != nil {
		a.cleanupPreparedInstall(prepareCtx, connection, credentials, prepared)
		return "", err
	}
	started = true
	request.Passphrase = ""
	selected := "embedded:" + a.version + "/" + payload.Name
	go a.finishInstall(item, selected, cfg.Admin.RemoteExecutable, credentials, connection, prepared, handle)
	return handle.ID, nil
}

func (a *App) inspectInstallTarget(ctx context.Context, item state.ManagedServer, knownHosts, passphrase, remoteExecutable, remoteConfig string) (InstallPreviewView, serverpayload.Payload, terminal.Connection, error) {
	connection := terminal.Connection{
		ServerID: item.ID, Target: item.Target, Port: item.Port, Identity: item.Identity,
		KnownHosts: knownHosts, ConnectTimeout: 10 * time.Second,
	}
	command := "set -eu; test \"$(uname -s)\" = Linux; . /etc/os-release; test \"${ID:-}\" = ubuntu; printf '%s\\n' \"${VERSION_ID:-unknown}\"; uname -m"
	result, err := terminal.RunCommand(ctx, connection, terminal.Credentials{Passphrase: passphrase}, command, nil)
	if err != nil {
		return InstallPreviewView{}, serverpayload.Payload{}, connection, fmt.Errorf("проверить Ubuntu и архитектуру сервера: %w", err)
	}
	lines := splitLines(result.Stdout)
	if len(lines) != 2 {
		return InstallPreviewView{}, serverpayload.Payload{}, connection, errors.New("сервер вернул неожиданный ответ проверки Ubuntu")
	}
	architecture, err := admin.NormalizeArchitecture(lines[1])
	if err != nil {
		return InstallPreviewView{}, serverpayload.Payload{}, connection, err
	}
	payload, err := serverpayload.ForArchitecture(architecture)
	if err != nil {
		return InstallPreviewView{}, serverpayload.Payload{}, connection, err
	}
	preview := InstallPreviewView{
		UbuntuVersion: lines[0], Architecture: architecture, PayloadName: payload.Name,
		PayloadSize: int64(len(payload.Data)), PayloadSHA256: payload.SHA256,
		RemoteExecutable: remoteExecutable, RemoteConfig: remoteConfig,
	}
	return preview, payload, connection, nil
}

func (a *App) CreateUser(request UserRequest) (*controller.OperationResult, error) {
	ctx, cancel := context.WithTimeout(a.context(), 10*time.Minute)
	defer cancel()
	result, err := a.controller.CreateUserEmbedded(ctx, request.ServerID, request.Username, request.PublicKey, request.GrantSudo, request.Passphrase)
	request.Passphrase = ""
	return result, err
}

func (a *App) CaptureSnapshot(request SnapshotRequest) (*controller.SnapshotResult, error) {
	ctx, cancel := context.WithTimeout(a.context(), 15*time.Minute)
	defer cancel()
	result, err := a.controller.CaptureSnapshotEmbedded(ctx, request.ServerID, request.ForceBaseline, request.Passphrase)
	request.Passphrase = ""
	return result, err
}

func (a *App) Diff(id string) (inventory.Diff, error) {
	return a.controller.Diff(id)
}

func (a *App) SetLatestAsBaseline(id, confirmation string) error {
	if confirmation != "BASELINE "+id {
		return errors.New("для замены baseline введите BASELINE " + id)
	}
	return a.controller.SetLatestAsBaseline(id)
}

func (a *App) History(id string, limit int) ([]state.HistoryEntry, error) {
	if limit < 1 || limit > 200 {
		limit = 50
	}
	return a.controller.Store.History(id, limit)
}

func (a *App) AuditAll() ([]controller.FleetResult, error) {
	ctx, cancel := context.WithTimeout(a.context(), 30*time.Minute)
	defer cancel()
	return a.controller.AuditAllEmbedded(ctx)
}

func (a *App) SecuritySettings(id string) (SecuritySettings, error) {
	cfg, err := a.controller.Config(id)
	if err != nil {
		return SecuritySettings{}, err
	}
	s := cfg.Server
	return SecuritySettings{
		Profile: s.Profile, ManageSSH: s.ManageSSH, ManageFirewall: s.ManageFirewall,
		ManageFail2ban: s.ManageFail2ban, ManageAutomaticUpdates: s.ManageAutomaticUpdates,
		ManageAuditd: s.ManageAuditd, ManageAppArmor: s.ManageAppArmor, ManageTimeSync: s.ManageTimeSync,
		PasswordAuthentication: s.PasswordAuthentication, PermitRootLogin: s.PermitRootLogin,
		SSHAllowedCIDRs: strings.Join(s.SSHAllowedCIDRs, "\n"), AllowedTCPPorts: joinPorts(s.AllowedTCPPorts),
		AllowedUDPPorts: joinPorts(s.AllowedUDPPorts), AutomaticReboot: s.AutomaticReboot,
		AutomaticRebootTime: s.AutomaticRebootTime, BackupMarkers: strings.Join(s.BackupMarkers, "\n"),
		BackupMaxAgeHours: s.BackupMaxAgeHours, BackupRequired: s.BackupRequired,
	}, nil
}

func (a *App) SaveSecuritySettings(id string, settings SecuritySettings) error {
	cfg, err := a.controller.Config(id)
	if err != nil {
		return err
	}
	if settings.Profile != cfg.Server.Profile {
		if _, ok := profile.Get(settings.Profile); !ok {
			return fmt.Errorf("неизвестный профиль %q", settings.Profile)
		}
	}
	tcp, err := parsePorts(settings.AllowedTCPPorts)
	if err != nil {
		return fmt.Errorf("TCP-порты: %w", err)
	}
	udp, err := parsePorts(settings.AllowedUDPPorts)
	if err != nil {
		return fmt.Errorf("UDP-порты: %w", err)
	}
	s := &cfg.Server
	s.Profile = settings.Profile
	s.ManageSSH = settings.ManageSSH
	s.ManageFirewall = settings.ManageFirewall
	s.ManageFail2ban = settings.ManageFail2ban
	s.ManageAutomaticUpdates = settings.ManageAutomaticUpdates
	s.ManageAuditd = settings.ManageAuditd
	s.ManageAppArmor = settings.ManageAppArmor
	s.ManageTimeSync = settings.ManageTimeSync
	s.PasswordAuthentication = settings.PasswordAuthentication
	s.PermitRootLogin = settings.PermitRootLogin
	s.SSHAllowedCIDRs = splitLines(settings.SSHAllowedCIDRs)
	s.AllowedTCPPorts = tcp
	s.AllowedUDPPorts = udp
	s.AutomaticReboot = settings.AutomaticReboot
	s.AutomaticRebootTime = strings.TrimSpace(settings.AutomaticRebootTime)
	s.BackupMarkers = splitLines(settings.BackupMarkers)
	s.BackupMaxAgeHours = settings.BackupMaxAgeHours
	s.BackupRequired = settings.BackupRequired
	return a.controller.SaveConfig(id, cfg)
}

func (a *App) ApplyProfile(id, name string) error {
	return a.controller.ApplyProfile(id, name)
}

func (a *App) XHTTP(id string) (XHTTPView, error) {
	item, err := a.controller.Store.Server(id)
	if err != nil {
		return XHTTPView{}, err
	}
	setup, err := a.controller.LoadXHTTPConfig(id)
	if os.IsNotExist(err) {
		return XHTTPView{Configured: false, Guide: []GuideStep{}}, nil
	}
	if err != nil {
		return XHTTPView{}, err
	}
	return XHTTPView{Configured: true, Config: setup, Guide: guideSteps(workload.ManualGuide(setup, item.Target, item.Identity, item.Port, 18080))}, nil
}

func (a *App) ConfigureXHTTP(request XHTTPRequest) (XHTTPView, error) {
	panelPort := request.PanelPort
	previous, previousErr := a.controller.LoadXHTTPConfig(request.ServerID)
	if previousErr != nil && !os.IsNotExist(previousErr) {
		return XHTTPView{}, previousErr
	}
	if previousErr == nil && panelPort == 0 {
		panelPort = previous.PanelPort
	}
	setup, err := workload.NewXHTTPConfig(request.Domain, request.Email, request.ServerIP, panelPort)
	if err != nil {
		return XHTTPView{}, err
	}
	if previousErr == nil {
		// The path is a security boundary and a user bookmark. Configuration
		// updates must not silently rotate it; a future explicit rotation flow
		// can replace it transactionally.
		setup.WebBasePath = previous.WebBasePath
	}
	if _, _, err := a.controller.ConfigureXHTTP(request.ServerID, setup); err != nil {
		return XHTTPView{}, err
	}
	return a.XHTTP(request.ServerID)
}

func (a *App) RunXHTTP(request XHTTPActionRequest) (*controller.OperationResult, error) {
	if !workload.IsXHTTPAction(request.Action) {
		return nil, errors.New("XHTTP-действие должно быть plan, apply или verify")
	}
	if request.Action == "apply" && request.Confirmation != "XHTTP APPLY "+request.ServerID {
		return nil, errors.New("для установки введите XHTTP APPLY " + request.ServerID)
	}
	setup, err := a.controller.LoadXHTTPConfig(request.ServerID)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(a.context(), 30*time.Minute)
	defer cancel()
	result, err := a.controller.RunWorkloadEmbedded(ctx, request.ServerID, workload.XHTTPModule, request.Action, setup, request.Action == "apply", request.Passphrase)
	request.Passphrase = ""
	return result, err
}

func (a *App) finishBootstrap(id string, handle terminal.Handle) {
	if err := <-handle.Done; err != nil {
		a.emit("bootstrap:failed", map[string]string{"server_id": id, "error": err.Error()})
		return
	}
	item, path, err := a.connectionDetails(id)
	if err == nil {
		ctx, cancel := context.WithTimeout(a.context(), 45*time.Second)
		result, runErr := terminal.RunCommand(ctx, terminal.Connection{
			ServerID: id, Target: item.Target, Port: item.Port, Identity: item.Identity,
			KnownHosts: path, ConnectTimeout: 10 * time.Second,
		}, terminal.Credentials{}, "printf '%s\\n' 'bastionctl-key-ok'", nil)
		cancel()
		if runErr != nil || strings.TrimSpace(result.Stdout) != "bastionctl-key-ok" {
			if runErr != nil {
				err = runErr
			} else {
				err = errors.New("сервер не подтвердил проверочный вход по ключу")
			}
		}
	}
	if err == nil {
		_, err = a.controller.CompleteBootstrap(id)
	}
	if err != nil {
		a.emit("bootstrap:failed", map[string]string{"server_id": id, "error": err.Error()})
		return
	}
	a.emit("bootstrap:completed", map[string]string{"server_id": id})
}

func (a *App) finishInstall(item state.ManagedServer, selected, executable string, credentials terminal.Credentials, connection terminal.Connection, prepared *admin.PreparedInstall, handle terminal.Handle) {
	defer prepared.Close()
	commandErr := <-handle.Done
	r := report.New(a.version, "admin", "install", item.Target)
	if commandErr != nil {
		ctx, cancel := context.WithTimeout(a.context(), 30*time.Second)
		a.cleanupPreparedInstall(ctx, connection, credentials, prepared)
		cancel()
		r.Add(report.Result{Control: "install", Status: report.Fail, Severity: "critical", Message: "интерактивная установка завершилась с ошибкой; был запрошен откат", Details: map[string]string{"error": commandErr.Error(), "recovery": "проверьте executable, config и /etc/sudoers.d/bastionctl через rescue/root-консоль"}})
	} else {
		ctx, cancel := context.WithTimeout(a.context(), 45*time.Second)
		result, verifyErr := terminal.RunCommand(ctx, connection, credentials, "sudo -n "+quoteRemote(executable)+" version", nil)
		cancel()
		if verifyErr != nil {
			r.Add(report.Result{Control: "install-verify", Status: report.Fail, Severity: "critical", Message: "файлы установлены, но проверка серверного компонента не удалась", Details: map[string]string{"error": verifyErr.Error()}})
		} else if installedVersion := strings.TrimSpace(result.Stdout); installedVersion != a.version {
			r.Add(report.Result{Control: "install-version", Status: report.Fail, Severity: "critical", Message: "версия встроенного и установленного компонентов не совпала", Details: map[string]string{"expected": a.version, "installed": installedVersion}})
		} else {
			r.Add(report.Result{Control: "architecture", Status: report.Pass, Severity: "high", Message: "архитектура Ubuntu подтверждена", Details: map[string]string{"architecture": prepared.Architecture}})
			r.Add(report.Result{Control: "upload", Status: report.Pass, Severity: "high", Message: "SHA-256 встроенного компонента и загруженных файлов проверен", Details: map[string]string{"payload": prepared.PayloadName, "sha256": prepared.PayloadSHA256}})
			r.Add(report.Result{Control: "install", Status: report.Changed, Severity: "critical", Message: "серверная часть и конфигурация установлены", Changed: true, Details: map[string]string{"executable": executable, "version": strings.TrimSpace(result.Stdout)}})
			r.Add(report.Result{Control: "sudo-policy", Status: report.Changed, Severity: "critical", Message: "установлена ограниченная NOPASSWD-политика bastionctl", Changed: true})
		}
	}
	operation, recordErr := a.controller.RecordInstall(item.ID, selected, r)
	credentials.Passphrase = ""
	if recordErr != nil {
		a.emit("install:failed", map[string]string{"server_id": item.ID, "error": recordErr.Error()})
		return
	}
	if r.HasFailures() {
		a.emit("install:failed", map[string]any{"server_id": item.ID, "operation": operation, "error": "установка не прошла проверку"})
		return
	}
	a.emit("install:completed", operation)
}

func (a *App) cleanupPreparedInstall(ctx context.Context, connection terminal.Connection, credentials terminal.Credentials, prepared *admin.PreparedInstall) {
	command, err := prepared.CleanupCommand()
	if err == nil {
		_, _ = terminal.RunCommand(ctx, connection, credentials, command, nil)
	}
}

func quoteRemote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}

func (a *App) context() context.Context {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.ctx == nil {
		return context.Background()
	}
	return a.ctx
}

func (a *App) connectionDetails(id string) (state.ManagedServer, string, error) {
	item, err := a.controller.Store.Server(id)
	if err != nil {
		return state.ManagedServer{}, "", err
	}
	path, err := a.controller.KnownHostsPath(id)
	return item, path, err
}

func (a *App) serverView(item state.ManagedServer) ServerView {
	path, _ := a.controller.KnownHostsPath(item.ID)
	return ServerView{
		ID: item.ID, Name: item.Name, Target: item.Target, Port: item.Port, Identity: item.Identity,
		Profile: item.Profile, BootstrapTarget: item.BootstrapTarget,
		BootstrapPending: item.BootstrapPending, HostKeyTrusted: terminal.HasPinnedHostKey(path),
		LastSeenAt: item.LastSeenAt, LastAction: item.LastAction, LastStatus: item.LastStatus,
	}
}

func probeTarget(item state.ManagedServer) string {
	if item.BootstrapPending && item.BootstrapTarget != "" {
		return item.BootstrapTarget
	}
	return item.Target
}

type address string

func (a address) Network() string        { return "tcp" }
func (a address) String() string         { return string(a) }
func stringAddress(value string) address { return address(value) }

func joinPorts(values []int) string {
	parts := make([]string, len(values))
	for index, value := range values {
		parts[index] = strconv.Itoa(value)
	}
	return strings.Join(parts, ", ")
}

func parsePorts(value string) ([]int, error) {
	fields := strings.FieldsFunc(value, func(char rune) bool { return char == ',' || char == ';' || char == '\n' || char == ' ' || char == '\t' })
	seen := make(map[int]struct{}, len(fields))
	result := make([]int, 0, len(fields))
	for _, field := range fields {
		port, err := strconv.Atoi(field)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("%q не является портом 1..65535", field)
		}
		if _, ok := seen[port]; !ok {
			seen[port] = struct{}{}
			result = append(result, port)
		}
	}
	sort.Ints(result)
	return result, nil
}

func splitLines(value string) []string {
	result := make([]string, 0)
	for _, item := range strings.FieldsFunc(value, func(char rune) bool { return char == '\n' || char == ',' || char == ';' }) {
		if item = strings.TrimSpace(item); item != "" {
			result = append(result, item)
		}
	}
	return result
}

func guideSteps(values []workload.ManualStep) []GuideStep {
	result := make([]GuideStep, 0, len(values))
	for _, item := range values {
		result = append(result, GuideStep{Title: item.Title, Details: append([]string(nil), item.Details...)})
	}
	return result
}
