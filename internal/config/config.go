package config

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type Config struct {
	Server ServerConfig
	Admin  AdminConfig
}

type ServerConfig struct {
	Profile                     string
	AdminUser                   string
	ManageSSH                   bool
	ManageFirewall              bool
	ManageFail2ban              bool
	ManageAutomaticUpdates      bool
	ManageSysctl                bool
	ManageJournald              bool
	ManageAuditd                bool
	ManageAppArmor              bool
	ManageTimeSync              bool
	ManagePermissions           bool
	PasswordAuthentication      bool
	PermitRootLogin             bool
	AllowTCPForwarding          bool
	AllowStreamLocalForwarding  bool
	AllowAgentForwarding        bool
	X11Forwarding               bool
	MaxAuthTries                int
	LoginGraceTime              int
	ClientAliveInterval         int
	ClientAliveCountMax         int
	SSHAllowedCIDRs             []string
	SSHLocalForwardDestinations []string
	AllowedTCPPorts             []int
	AllowedUDPPorts             []int
	Fail2banMaxRetry            int
	Fail2banFindTime            string
	Fail2banBanTime             string
	AutomaticReboot             bool
	AutomaticRebootTime         string
	JournalMaxUse               string
	RPFilter                    int
	BackupMarkers               []string
	BackupMaxAgeHours           int
	BackupRequired              bool
}

type AdminConfig struct {
	ConnectTimeout        int
	StrictHostKeyChecking bool
	RemoteExecutable      string
	RemoteConfig          string
}

func Defaults() Config {
	return Config{
		Server: ServerConfig{
			Profile: "minimal", AdminUser: "",
			ManageSSH: true, ManageFirewall: true, ManageFail2ban: true,
			ManageAutomaticUpdates: true, ManageSysctl: true, ManageJournald: true,
			ManageAuditd: true, ManageAppArmor: true, ManageTimeSync: true, ManagePermissions: true,
			PasswordAuthentication: false, PermitRootLogin: false,
			AllowTCPForwarding: false, AllowStreamLocalForwarding: false,
			AllowAgentForwarding: false, X11Forwarding: false,
			MaxAuthTries: 3, LoginGraceTime: 30, ClientAliveInterval: 300, ClientAliveCountMax: 2,
			SSHAllowedCIDRs: []string{}, SSHLocalForwardDestinations: []string{},
			AllowedTCPPorts: []int{}, AllowedUDPPorts: []int{},
			Fail2banMaxRetry: 5, Fail2banFindTime: "10m", Fail2banBanTime: "1h",
			AutomaticReboot: false, AutomaticRebootTime: "03:30", JournalMaxUse: "1G", RPFilter: 2,
			BackupMarkers: []string{}, BackupMaxAgeHours: 26, BackupRequired: false,
		},
		Admin: AdminConfig{
			ConnectTimeout: 10, StrictHostKeyChecking: true,
			RemoteExecutable: "/usr/local/bin/bastionctl", RemoteConfig: "/etc/bastionctl/config.toml",
		},
	}
}

func Load(path string) (Config, error) {
	cfg := Defaults()
	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("открыть конфигурацию %q: %w", path, err)
	}
	defer file.Close()

	section := ""
	seen := map[string]int{}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(stripComment(scanner.Text()))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			if section != "server" && section != "admin" {
				return Config{}, fmt.Errorf("строка %d: неизвестная секция [%s]", lineNumber, section)
			}
			continue
		}
		if section == "" {
			return Config{}, fmt.Errorf("строка %d: параметр должен находиться в секции", lineNumber)
		}
		key, raw, ok := splitAssignment(line)
		if !ok {
			return Config{}, fmt.Errorf("строка %d: ожидается key = value", lineNumber)
		}
		fullKey := section + "." + key
		if previous, exists := seen[fullKey]; exists {
			return Config{}, fmt.Errorf("строка %d: %s уже задан на строке %d", lineNumber, fullKey, previous)
		}
		seen[fullKey] = lineNumber
		if err := assign(&cfg, section, key, raw); err != nil {
			return Config{}, fmt.Errorf("строка %d (%s): %w", lineNumber, fullKey, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return Config{}, fmt.Errorf("прочитать конфигурацию: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func stripComment(line string) string {
	inString := false
	escaped := false
	for index, char := range line {
		if escaped {
			escaped = false
			continue
		}
		if char == '\\' && inString {
			escaped = true
			continue
		}
		if char == '"' {
			inString = !inString
			continue
		}
		if char == '#' && !inString {
			return line[:index]
		}
	}
	return line
}

func splitAssignment(line string) (string, string, bool) {
	inString := false
	escaped := false
	for index, char := range line {
		if escaped {
			escaped = false
			continue
		}
		if char == '\\' && inString {
			escaped = true
			continue
		}
		if char == '"' {
			inString = !inString
			continue
		}
		if char == '=' && !inString {
			key := strings.TrimSpace(line[:index])
			value := strings.TrimSpace(line[index+1:])
			if key == "" || value == "" || !regexp.MustCompile(`^[a-z][a-z0-9_]*$`).MatchString(key) {
				return "", "", false
			}
			return key, value, true
		}
	}
	return "", "", false
}

func assign(cfg *Config, section, key, raw string) error {
	if section == "server" {
		s := &cfg.Server
		switch key {
		case "admin_user":
			return parseIntoString(raw, &s.AdminUser)
		case "profile":
			return parseIntoString(raw, &s.Profile)
		case "manage_ssh":
			return parseIntoBool(raw, &s.ManageSSH)
		case "manage_firewall":
			return parseIntoBool(raw, &s.ManageFirewall)
		case "manage_fail2ban":
			return parseIntoBool(raw, &s.ManageFail2ban)
		case "manage_automatic_updates":
			return parseIntoBool(raw, &s.ManageAutomaticUpdates)
		case "manage_sysctl":
			return parseIntoBool(raw, &s.ManageSysctl)
		case "manage_journald":
			return parseIntoBool(raw, &s.ManageJournald)
		case "manage_auditd":
			return parseIntoBool(raw, &s.ManageAuditd)
		case "manage_apparmor":
			return parseIntoBool(raw, &s.ManageAppArmor)
		case "manage_time_sync":
			return parseIntoBool(raw, &s.ManageTimeSync)
		case "manage_permissions":
			return parseIntoBool(raw, &s.ManagePermissions)
		case "password_authentication":
			return parseIntoBool(raw, &s.PasswordAuthentication)
		case "permit_root_login":
			return parseIntoBool(raw, &s.PermitRootLogin)
		case "allow_tcp_forwarding":
			return parseIntoBool(raw, &s.AllowTCPForwarding)
		case "allow_streamlocal_forwarding":
			return parseIntoBool(raw, &s.AllowStreamLocalForwarding)
		case "allow_agent_forwarding":
			return parseIntoBool(raw, &s.AllowAgentForwarding)
		case "x11_forwarding":
			return parseIntoBool(raw, &s.X11Forwarding)
		case "max_auth_tries":
			return parseIntoInt(raw, &s.MaxAuthTries)
		case "login_grace_time":
			return parseIntoInt(raw, &s.LoginGraceTime)
		case "client_alive_interval":
			return parseIntoInt(raw, &s.ClientAliveInterval)
		case "client_alive_count_max":
			return parseIntoInt(raw, &s.ClientAliveCountMax)
		case "ssh_allowed_cidrs":
			return parseStringArray(raw, &s.SSHAllowedCIDRs)
		case "ssh_local_forward_destinations":
			return parseStringArray(raw, &s.SSHLocalForwardDestinations)
		case "allowed_tcp_ports":
			return parseIntArray(raw, &s.AllowedTCPPorts)
		case "allowed_udp_ports":
			return parseIntArray(raw, &s.AllowedUDPPorts)
		case "fail2ban_maxretry":
			return parseIntoInt(raw, &s.Fail2banMaxRetry)
		case "fail2ban_findtime":
			return parseIntoString(raw, &s.Fail2banFindTime)
		case "fail2ban_bantime":
			return parseIntoString(raw, &s.Fail2banBanTime)
		case "automatic_reboot":
			return parseIntoBool(raw, &s.AutomaticReboot)
		case "automatic_reboot_time":
			return parseIntoString(raw, &s.AutomaticRebootTime)
		case "journal_max_use":
			return parseIntoString(raw, &s.JournalMaxUse)
		case "rp_filter":
			return parseIntoInt(raw, &s.RPFilter)
		case "backup_markers":
			return parseStringArray(raw, &s.BackupMarkers)
		case "backup_max_age_hours":
			return parseIntoInt(raw, &s.BackupMaxAgeHours)
		case "backup_required":
			return parseIntoBool(raw, &s.BackupRequired)
		default:
			return errors.New("неизвестный параметр")
		}
	}

	a := &cfg.Admin
	switch key {
	case "connect_timeout":
		return parseIntoInt(raw, &a.ConnectTimeout)
	case "strict_host_key_checking":
		return parseIntoBool(raw, &a.StrictHostKeyChecking)
	case "remote_executable":
		return parseIntoString(raw, &a.RemoteExecutable)
	case "remote_config":
		return parseIntoString(raw, &a.RemoteConfig)
	default:
		return errors.New("неизвестный параметр")
	}
}

func parseIntoString(raw string, destination *string) error {
	value, err := strconv.Unquote(raw)
	if err != nil {
		return errors.New("ожидается строка в двойных кавычках")
	}
	*destination = value
	return nil
}

func parseIntoBool(raw string, destination *bool) error {
	if raw != "true" && raw != "false" {
		return errors.New("ожидается true или false")
	}
	*destination = raw == "true"
	return nil
}

func parseIntoInt(raw string, destination *int) error {
	value, err := strconv.Atoi(raw)
	if err != nil {
		return errors.New("ожидается целое число")
	}
	*destination = value
	return nil
}

func splitArray(raw string) ([]string, error) {
	if len(raw) < 2 || raw[0] != '[' || raw[len(raw)-1] != ']' {
		return nil, errors.New("ожидается массив [...]")
	}
	body := strings.TrimSpace(raw[1 : len(raw)-1])
	if body == "" {
		return []string{}, nil
	}
	var parts []string
	start := 0
	inString := false
	escaped := false
	for index, char := range body {
		if escaped {
			escaped = false
			continue
		}
		if char == '\\' && inString {
			escaped = true
			continue
		}
		if char == '"' {
			inString = !inString
			continue
		}
		if char == ',' && !inString {
			part := strings.TrimSpace(body[start:index])
			if part == "" {
				return nil, errors.New("пустой элемент массива")
			}
			parts = append(parts, part)
			start = index + 1
		}
	}
	if inString {
		return nil, errors.New("незакрытая строка в массиве")
	}
	last := strings.TrimSpace(body[start:])
	if last == "" {
		return nil, errors.New("лишняя запятая в массиве")
	}
	return append(parts, last), nil
}

func parseStringArray(raw string, destination *[]string) error {
	parts, err := splitArray(raw)
	if err != nil {
		return err
	}
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		value, err := strconv.Unquote(part)
		if err != nil {
			return errors.New("элементы массива должны быть строками")
		}
		values = append(values, value)
	}
	*destination = values
	return nil
}

func parseIntArray(raw string, destination *[]int) error {
	parts, err := splitArray(raw)
	if err != nil {
		return err
	}
	values := make([]int, 0, len(parts))
	for _, part := range parts {
		value, err := strconv.Atoi(part)
		if err != nil {
			return errors.New("элементы массива должны быть целыми числами")
		}
		values = append(values, value)
	}
	*destination = values
	return nil
}

var (
	usernamePattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	durationPattern = regexp.MustCompile(`^[1-9][0-9]*[smhdw]$`)
	timePattern     = regexp.MustCompile(`^(?:[01][0-9]|2[0-3]):[0-5][0-9]$`)
	sizePattern     = regexp.MustCompile(`^[1-9][0-9]*[KMGTP]?$`)
	remotePath      = regexp.MustCompile(`^/[A-Za-z0-9_./-]+$`)
	profilePattern  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
)

func (c *Config) Validate() error {
	s := &c.Server
	if !profilePattern.MatchString(s.Profile) {
		return errors.New("server.profile: недопустимое имя профиля")
	}
	if s.AdminUser != "" && !usernamePattern.MatchString(s.AdminUser) {
		return errors.New("server.admin_user: недопустимое имя пользователя")
	}
	if s.ManageSSH && (s.PasswordAuthentication || s.PermitRootLogin) {
		return errors.New("управляемый SSH-профиль требует password_authentication=false и permit_root_login=false")
	}
	if s.MaxAuthTries < 1 || s.MaxAuthTries > 10 {
		return errors.New("server.max_auth_tries должен быть в диапазоне 1..10")
	}
	if s.LoginGraceTime < 10 || s.LoginGraceTime > 120 {
		return errors.New("server.login_grace_time должен быть в диапазоне 10..120")
	}
	if s.ClientAliveInterval < 0 || s.ClientAliveInterval > 3600 || s.ClientAliveCountMax < 0 || s.ClientAliveCountMax > 10 {
		return errors.New("недопустимые client_alive_* параметры")
	}
	if s.Fail2banMaxRetry < 1 || s.Fail2banMaxRetry > 20 {
		return errors.New("server.fail2ban_maxretry должен быть в диапазоне 1..20")
	}
	if !durationPattern.MatchString(s.Fail2banFindTime) || !durationPattern.MatchString(s.Fail2banBanTime) {
		return errors.New("fail2ban_findtime и fail2ban_bantime должны иметь вид 10m, 1h или 1d")
	}
	if !timePattern.MatchString(s.AutomaticRebootTime) {
		return errors.New("server.automatic_reboot_time должен иметь формат HH:MM")
	}
	if !sizePattern.MatchString(s.JournalMaxUse) {
		return errors.New("server.journal_max_use должен иметь вид 512M или 1G")
	}
	if s.RPFilter != 1 && s.RPFilter != 2 {
		return errors.New("server.rp_filter должен быть 1 или 2")
	}
	if s.BackupMaxAgeHours < 1 || s.BackupMaxAgeHours > 24*365 {
		return errors.New("server.backup_max_age_hours должен быть в диапазоне 1..8760")
	}
	for _, path := range s.BackupMarkers {
		if !remotePath.MatchString(path) || strings.Contains(path, "..") {
			return fmt.Errorf("server.backup_markers: %q не является безопасным абсолютным POSIX-путём", path)
		}
	}
	for _, cidr := range s.SSHAllowedCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("server.ssh_allowed_cidrs: %q не является CIDR", cidr)
		}
	}
	if len(s.SSHLocalForwardDestinations) > 0 {
		if !s.ManageSSH || s.AdminUser == "" {
			return errors.New("server.ssh_local_forward_destinations требует manage_ssh=true и admin_user")
		}
		if s.AllowTCPForwarding {
			return errors.New("server.ssh_local_forward_destinations несовместим с глобальным allow_tcp_forwarding=true")
		}
	}
	var err error
	s.SSHLocalForwardDestinations, err = validateLocalForwardDestinations(s.SSHLocalForwardDestinations)
	if err != nil {
		return err
	}
	if s.AllowedTCPPorts, err = validatePorts("server.allowed_tcp_ports", s.AllowedTCPPorts); err != nil {
		return err
	}
	if s.AllowedUDPPorts, err = validatePorts("server.allowed_udp_ports", s.AllowedUDPPorts); err != nil {
		return err
	}
	if c.Admin.ConnectTimeout < 1 || c.Admin.ConnectTimeout > 120 {
		return errors.New("admin.connect_timeout должен быть в диапазоне 1..120")
	}
	if !remotePath.MatchString(c.Admin.RemoteExecutable) || strings.Contains(c.Admin.RemoteExecutable, "..") {
		return errors.New("admin.remote_executable: требуется безопасный абсолютный POSIX-путь")
	}
	if !remotePath.MatchString(c.Admin.RemoteConfig) || strings.Contains(c.Admin.RemoteConfig, "..") {
		return errors.New("admin.remote_config: требуется безопасный абсолютный POSIX-путь")
	}
	return nil
}

func Render(c Config) ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	s := c.Server
	a := c.Admin
	var output strings.Builder
	fmt.Fprintln(&output, "# Managed by bastionctl controller. Review before apply.")
	fmt.Fprintln(&output, "[server]")
	fmt.Fprintf(&output, "profile = %s\n", strconv.Quote(s.Profile))
	fmt.Fprintf(&output, "admin_user = %s\n\n", strconv.Quote(s.AdminUser))
	fmt.Fprintf(&output, "manage_ssh = %t\n", s.ManageSSH)
	fmt.Fprintf(&output, "manage_firewall = %t\n", s.ManageFirewall)
	fmt.Fprintf(&output, "manage_fail2ban = %t\n", s.ManageFail2ban)
	fmt.Fprintf(&output, "manage_automatic_updates = %t\n", s.ManageAutomaticUpdates)
	fmt.Fprintf(&output, "manage_sysctl = %t\n", s.ManageSysctl)
	fmt.Fprintf(&output, "manage_journald = %t\n", s.ManageJournald)
	fmt.Fprintf(&output, "manage_auditd = %t\n", s.ManageAuditd)
	fmt.Fprintf(&output, "manage_apparmor = %t\n", s.ManageAppArmor)
	fmt.Fprintf(&output, "manage_time_sync = %t\n", s.ManageTimeSync)
	fmt.Fprintf(&output, "manage_permissions = %t\n\n", s.ManagePermissions)
	fmt.Fprintf(&output, "password_authentication = %t\n", s.PasswordAuthentication)
	fmt.Fprintf(&output, "permit_root_login = %t\n", s.PermitRootLogin)
	fmt.Fprintf(&output, "allow_tcp_forwarding = %t\n", s.AllowTCPForwarding)
	fmt.Fprintf(&output, "allow_streamlocal_forwarding = %t\n", s.AllowStreamLocalForwarding)
	fmt.Fprintf(&output, "allow_agent_forwarding = %t\n", s.AllowAgentForwarding)
	fmt.Fprintf(&output, "x11_forwarding = %t\n", s.X11Forwarding)
	fmt.Fprintf(&output, "max_auth_tries = %d\n", s.MaxAuthTries)
	fmt.Fprintf(&output, "login_grace_time = %d\n", s.LoginGraceTime)
	fmt.Fprintf(&output, "client_alive_interval = %d\n", s.ClientAliveInterval)
	fmt.Fprintf(&output, "client_alive_count_max = %d\n\n", s.ClientAliveCountMax)
	fmt.Fprintf(&output, "ssh_allowed_cidrs = %s\n", renderStringArray(s.SSHAllowedCIDRs))
	fmt.Fprintf(&output, "ssh_local_forward_destinations = %s\n", renderStringArray(s.SSHLocalForwardDestinations))
	fmt.Fprintf(&output, "allowed_tcp_ports = %s\n", renderIntArray(s.AllowedTCPPorts))
	fmt.Fprintf(&output, "allowed_udp_ports = %s\n\n", renderIntArray(s.AllowedUDPPorts))
	fmt.Fprintf(&output, "fail2ban_maxretry = %d\n", s.Fail2banMaxRetry)
	fmt.Fprintf(&output, "fail2ban_findtime = %s\n", strconv.Quote(s.Fail2banFindTime))
	fmt.Fprintf(&output, "fail2ban_bantime = %s\n\n", strconv.Quote(s.Fail2banBanTime))
	fmt.Fprintf(&output, "automatic_reboot = %t\n", s.AutomaticReboot)
	fmt.Fprintf(&output, "automatic_reboot_time = %s\n", strconv.Quote(s.AutomaticRebootTime))
	fmt.Fprintf(&output, "journal_max_use = %s\n", strconv.Quote(s.JournalMaxUse))
	fmt.Fprintf(&output, "rp_filter = %d\n\n", s.RPFilter)
	fmt.Fprintf(&output, "backup_markers = %s\n", renderStringArray(s.BackupMarkers))
	fmt.Fprintf(&output, "backup_max_age_hours = %d\n", s.BackupMaxAgeHours)
	fmt.Fprintf(&output, "backup_required = %t\n\n", s.BackupRequired)
	fmt.Fprintln(&output, "[admin]")
	fmt.Fprintf(&output, "connect_timeout = %d\n", a.ConnectTimeout)
	fmt.Fprintf(&output, "strict_host_key_checking = %t\n", a.StrictHostKeyChecking)
	fmt.Fprintf(&output, "remote_executable = %s\n", strconv.Quote(a.RemoteExecutable))
	fmt.Fprintf(&output, "remote_config = %s\n", strconv.Quote(a.RemoteConfig))
	return []byte(output.String()), nil
}

func renderStringArray(values []string) string {
	quoted := make([]string, len(values))
	for index, value := range values {
		quoted[index] = strconv.Quote(value)
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

func renderIntArray(values []int) string {
	parts := make([]string, len(values))
	for index, value := range values {
		parts[index] = strconv.Itoa(value)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func validatePorts(name string, ports []int) ([]int, error) {
	unique := make(map[int]struct{}, len(ports))
	for _, port := range ports {
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("%s: порт %d вне диапазона 1..65535", name, port)
		}
		unique[port] = struct{}{}
	}
	result := make([]int, 0, len(unique))
	for port := range unique {
		result = append(result, port)
	}
	sort.Ints(result)
	return result, nil
}

func validateLocalForwardDestinations(values []string) ([]string, error) {
	unique := make(map[string]struct{}, len(values))
	for _, value := range values {
		host, portRaw, err := net.SplitHostPort(value)
		if err != nil || host != "127.0.0.1" {
			return nil, fmt.Errorf("server.ssh_local_forward_destinations: %q должен иметь вид 127.0.0.1:PORT", value)
		}
		port, err := strconv.Atoi(portRaw)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("server.ssh_local_forward_destinations: недопустимый порт в %q", value)
		}
		unique[net.JoinHostPort(host, strconv.Itoa(port))] = struct{}{}
	}
	result := make([]string, 0, len(unique))
	for value := range unique {
		result = append(result, value)
	}
	sort.Strings(result)
	return result, nil
}
