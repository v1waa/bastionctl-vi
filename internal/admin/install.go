package admin

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"bastionctl/internal/config"
	"bastionctl/internal/report"
)

type InstallOptions struct {
	Connection      Options
	BinaryPath      string
	ConfigPath      string
	InstallSudo     bool
	ExpectedArch    string
	InteractiveSudo bool
	Input           io.Reader
	Output          io.Writer
}

func DetectArchitecture(ctx context.Context, cfg config.AdminConfig, options Options) (string, error) {
	stdout, stderr, err := runRawSSH(ctx, cfg, options, remoteCommand([]string{"uname", "-m"}), 30*time.Second)
	if err != nil {
		message := strings.TrimSpace(string(stderr))
		if message == "" {
			message = err.Error()
		}
		return "", errors.New(message)
	}
	return NormalizeArchitecture(string(stdout))
}

func NormalizeArchitecture(value string) (string, error) {
	switch strings.TrimSpace(value) {
	case "x86_64", "amd64":
		return "amd64", nil
	case "aarch64", "arm64":
		return "arm64", nil
	default:
		return "", fmt.Errorf("неподдерживаемая архитектура сервера %q", strings.TrimSpace(value))
	}
}

func Install(ctx context.Context, cfg config.AdminConfig, version string, options InstallOptions) *report.Report {
	r := report.New(version, "admin", "install", options.Connection.Target)
	if err := validateConnection(options.Connection); err != nil {
		r.Add(report.Result{Control: "connection", Status: report.Fail, Severity: "critical", Message: err.Error()})
		return r
	}
	architecture, err := DetectArchitecture(ctx, cfg, options.Connection)
	if err != nil {
		r.Add(report.Result{Control: "architecture", Status: report.Fail, Severity: "critical", Message: "не удалось определить архитектуру сервера", Details: map[string]string{"error": err.Error()}})
		return r
	}
	if options.ExpectedArch != "" && options.ExpectedArch != architecture {
		r.Add(report.Result{Control: "architecture", Status: report.Fail, Severity: "critical", Message: "архитектура сервера не совпадает с выбранной сборкой", Details: map[string]string{"server": architecture, "expected": options.ExpectedArch}})
		return r
	}
	localArch, err := ELFArchitecture(options.BinaryPath)
	if err != nil {
		r.Add(report.Result{Control: "server-binary", Status: report.Fail, Severity: "critical", Message: "серверный бинарник не прошёл проверку", Details: map[string]string{"error": err.Error()}})
		return r
	}
	if localArch != architecture {
		r.Add(report.Result{Control: "server-binary", Status: report.Fail, Severity: "critical", Message: "выбран бинарник другой архитектуры", Details: map[string]string{"binary": localArch, "server": architecture}})
		return r
	}
	if err := validateUploadFile(options.ConfigPath, 2<<20); err != nil {
		r.Add(report.Result{Control: "config", Status: report.Fail, Severity: "critical", Message: err.Error()})
		return r
	}

	suffix, err := randomSuffix()
	if err != nil {
		r.Add(report.Result{Control: "upload", Status: report.Fail, Severity: "critical", Message: err.Error()})
		return r
	}
	remoteBinary := "/tmp/bastionctl-bin-" + suffix
	remoteConfig := "/tmp/bastionctl-config-" + suffix
	remoteSudoers := "/tmp/bastionctl-sudoers-" + suffix
	backupBinary := "/tmp/bastionctl-old-bin-" + suffix
	backupConfig := "/tmp/bastionctl-old-config-" + suffix
	backupSudoers := "/tmp/bastionctl-old-sudoers-" + suffix
	localSudoers := ""
	sudo := "sudo -n"
	if options.InteractiveSudo {
		sudo = "sudo"
	}
	if options.InstallSudo {
		localSudoers, err = createSudoersFile(options.Connection.Target, cfg)
		if err != nil {
			r.Add(report.Result{Control: "sudo-policy", Status: report.Fail, Severity: "critical", Message: err.Error()})
			return r
		}
		defer os.Remove(localSudoers)
	}

	uploads := [][2]string{{options.BinaryPath, remoteBinary}, {options.ConfigPath, remoteConfig}}
	if localSudoers != "" {
		uploads = append(uploads, [2]string{localSudoers, remoteSudoers})
	}
	for _, item := range uploads {
		if err := copyToRemote(ctx, cfg, options.Connection, item[0], item[1]); err != nil {
			cleanupRemote(ctx, cfg, options.Connection, remoteBinary, remoteConfig, remoteSudoers)
			r.Add(report.Result{Control: "upload", Status: report.Fail, Severity: "critical", Message: "не удалось загрузить файлы на сервер", Details: map[string]string{"error": err.Error()}})
			return r
		}
	}
	binaryDigest, _ := fileSHA256(options.BinaryPath)
	configDigest, _ := fileSHA256(options.ConfigPath)
	commands := []string{
		"printf '%s  %s\\n' " + shellQuote(binaryDigest) + " " + shellQuote(remoteBinary) + " | sha256sum -c -",
		"printf '%s  %s\\n' " + shellQuote(configDigest) + " " + shellQuote(remoteConfig) + " | sha256sum -c -",
	}
	if localSudoers != "" {
		sudoDigest, _ := fileSHA256(localSudoers)
		commands = append(commands,
			"printf '%s  %s\\n' "+shellQuote(sudoDigest)+" "+shellQuote(remoteSudoers)+" | sha256sum -c -",
			sudo+" visudo -cf "+shellQuote(remoteSudoers),
		)
	}
	commands = append(commands,
		sudo+" install -m 0755 -o root -g root "+shellQuote(remoteBinary)+" "+shellQuote(cfg.RemoteExecutable),
		sudo+" install -d -m 0750 -o root -g root "+shellQuote(filepath.Dir(cfg.RemoteConfig)),
		sudo+" install -m 0600 -o root -g root "+shellQuote(remoteConfig)+" "+shellQuote(cfg.RemoteConfig),
		sudo+" "+shellQuote(cfg.RemoteExecutable)+" version",
	)
	if localSudoers != "" {
		commands = append(commands, sudo+" install -m 0440 -o root -g root "+shellQuote(remoteSudoers)+" /etc/sudoers.d/bastionctl")
	}
	prepare := []string{
		"install_started=0", "had_binary=0", "had_config=0", "had_sudoers=0",
		"if " + sudo + " test -e " + shellQuote(cfg.RemoteExecutable) + "; then " + sudo + " cp -p " + shellQuote(cfg.RemoteExecutable) + " " + shellQuote(backupBinary) + " && had_binary=1; fi",
		"if " + sudo + " test -e " + shellQuote(cfg.RemoteConfig) + "; then " + sudo + " cp -p " + shellQuote(cfg.RemoteConfig) + " " + shellQuote(backupConfig) + " && had_config=1; fi",
	}
	rollback := []string{
		"if [ \"$had_binary\" -eq 1 ]; then " + sudo + " cp -p " + shellQuote(backupBinary) + " " + shellQuote(cfg.RemoteExecutable) + "; else " + sudo + " rm -f " + shellQuote(cfg.RemoteExecutable) + "; fi",
		"if [ \"$had_config\" -eq 1 ]; then " + sudo + " cp -p " + shellQuote(backupConfig) + " " + shellQuote(cfg.RemoteConfig) + "; else " + sudo + " rm -f " + shellQuote(cfg.RemoteConfig) + "; fi",
	}
	if localSudoers != "" {
		prepare = append(prepare, "if "+sudo+" test -e /etc/sudoers.d/bastionctl; then "+sudo+" cp -p /etc/sudoers.d/bastionctl "+shellQuote(backupSudoers)+" && had_sudoers=1; fi")
		rollback = append(rollback, "if [ \"$had_sudoers\" -eq 1 ]; then "+sudo+" cp -p "+shellQuote(backupSudoers)+" /etc/sudoers.d/bastionctl; else "+sudo+" rm -f /etc/sudoers.d/bastionctl; fi")
	}
	prepare = append(prepare, "install_started=1")
	cleanupRoot := sudo + " rm -f " + shellQuote(backupBinary) + " " + shellQuote(backupConfig) + " " + shellQuote(backupSudoers)
	cleanupUser := "rm -f " + shellQuote(remoteBinary) + " " + shellQuote(remoteConfig) + " " + shellQuote(remoteSudoers)
	installCommand := "status=0; { " + strings.Join(prepare, " && ") + " && " + strings.Join(commands, " && ") +
		"; } || status=$?; if [ \"$status\" -ne 0 ] && [ \"$install_started\" -eq 1 ]; then if ! (" + strings.Join(rollback, " && ") +
		"); then printf '%s\\n' 'bastionctl: automatic install rollback failed' >&2; status=125; fi; fi; " +
		"if ! (" + cleanupRoot + " && " + cleanupUser + "); then printf '%s\\n' 'bastionctl: temporary file cleanup failed' >&2; status=125; fi; exit \"$status\""
	var stdout, stderr []byte
	var commandErr error
	if options.InteractiveSudo {
		stdout, stderr, commandErr = runInteractiveSSH(ctx, cfg, options.Connection, installCommand, options.Input, options.Output, 10*time.Minute)
	} else {
		stdout, stderr, commandErr = runRawSSH(ctx, cfg, options.Connection, installCommand, 10*time.Minute)
	}
	if commandErr != nil {
		cleanupRemote(ctx, cfg, options.Connection, remoteBinary, remoteConfig, remoteSudoers)
		r.Add(report.Result{Control: "install", Status: report.Fail, Severity: "critical", Message: "установка на сервере завершилась с ошибкой; запрошен автоматический откат прежних файлов", Details: map[string]string{"stderr": limit(strings.TrimSpace(string(stderr)), 4000), "recovery": "проверьте executable, config и /etc/sudoers.d/bastionctl через rescue/root-консоль"}})
		return r
	}
	installedVersion := lastNonEmptyLine(string(stdout))
	r.Add(report.Result{Control: "architecture", Status: report.Pass, Severity: "high", Message: "архитектура сервера подтверждена", Details: map[string]string{"architecture": architecture}})
	r.Add(report.Result{Control: "upload", Status: report.Pass, Severity: "high", Message: "SHA-256 загруженных файлов проверен"})
	r.Add(report.Result{Control: "install", Status: report.Changed, Severity: "critical", Message: "серверная часть и конфигурация установлены", Changed: true, Details: map[string]string{"executable": cfg.RemoteExecutable, "config": cfg.RemoteConfig, "version": installedVersion}})
	if localSudoers != "" {
		r.Add(report.Result{Control: "sudo-policy", Status: report.Changed, Severity: "critical", Message: "установлена ограниченная NOPASSWD-политика для команд bastionctl", Changed: true})
	}
	return r
}

func ELFArchitecture(path string) (string, error) {
	if err := validateUploadFile(path, 100<<20); err != nil {
		return "", err
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	header := make([]byte, 20)
	if _, err := io.ReadFull(file, header); err != nil {
		return "", err
	}
	return ELFArchitectureData(header)
}

// ELFArchitectureData validates the architecture fields of a Linux ELF64
// payload before it is ever sent to a managed server.
func ELFArchitectureData(data []byte) (string, error) {
	if len(data) < 20 {
		return "", errors.New("ELF-заголовок слишком короткий")
	}
	header := data[:20]
	if !bytes.Equal(header[:4], []byte{0x7f, 'E', 'L', 'F'}) || header[4] != 2 || header[5] != 1 {
		return "", errors.New("ожидается 64-битный little-endian ELF бинарник Linux")
	}
	machine := binary.LittleEndian.Uint16(header[18:20])
	switch machine {
	case 62:
		return "amd64", nil
	case 183:
		return "arm64", nil
	default:
		return "", fmt.Errorf("неподдерживаемый ELF machine %d", machine)
	}
}

func copyToRemote(ctx context.Context, cfg config.AdminConfig, options Options, local, remote string) error {
	scpPath, err := exec.LookPath("scp")
	if err != nil {
		return errors.New("OpenSSH scp не найден в PATH")
	}
	strict := "yes"
	if !cfg.StrictHostKeyChecking {
		strict = "accept-new"
	}
	args := []string{
		"-q", "-o", "BatchMode=yes", "-o", "PasswordAuthentication=no",
		"-o", "KbdInteractiveAuthentication=no", "-o", "StrictHostKeyChecking=" + strict,
		"-o", "ConnectTimeout=" + strconv.Itoa(cfg.ConnectTimeout), "-P", strconv.Itoa(options.Port),
	}
	if options.Identity != "" {
		args = append(args, "-i", options.Identity, "-o", "IdentitiesOnly=yes")
	}
	if options.KnownHostsFile != "" {
		args = append(args,
			"-o", "UserKnownHostsFile="+options.KnownHostsFile,
			"-o", "GlobalKnownHostsFile="+os.DevNull,
		)
	}
	args = append(args, "--", local, options.Target+":"+remote)
	commandCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(commandCtx, scpPath, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("scp: %s", limit(strings.TrimSpace(stderr.String()), 2000))
	}
	return nil
}

func createSudoersFile(target string, cfg config.AdminConfig) (string, error) {
	username := target[:strings.Index(target, "@")]
	commands := []string{
		cfg.RemoteExecutable + " server audit --config " + cfg.RemoteConfig + " --json",
		cfg.RemoteExecutable + " server plan --config " + cfg.RemoteConfig + " --json",
		cfg.RemoteExecutable + " server apply --config " + cfg.RemoteConfig + " --json --yes",
		cfg.RemoteExecutable + " server snapshot --config " + cfg.RemoteConfig + " --json",
		cfg.RemoteExecutable + " server reset-plan --config " + cfg.RemoteConfig + " --json",
		cfg.RemoteExecutable + " server reset --config " + cfg.RemoteConfig + " --json --yes",
		cfg.RemoteExecutable + " server user-add --config " + cfg.RemoteConfig + " --json --yes",
		cfg.RemoteExecutable + " server workload xhttp plan --config " + cfg.RemoteConfig + " --json",
		cfg.RemoteExecutable + " server workload xhttp apply --config " + cfg.RemoteConfig + " --json --yes",
		cfg.RemoteExecutable + " server workload xhttp verify --config " + cfg.RemoteConfig + " --json",
	}
	content := "# Managed by bastionctl.\nCmnd_Alias BASTIONCTL = " + strings.Join(commands, ", ") + "\n" + username + " ALL=(root) NOPASSWD: BASTIONCTL\n"
	file, err := os.CreateTemp("", "bastionctl-sudoers-*")
	if err != nil {
		return "", err
	}
	path := file.Name()
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		os.Remove(path)
		return "", err
	}
	if _, err := file.WriteString(content); err != nil {
		file.Close()
		os.Remove(path)
		return "", err
	}
	if err := file.Close(); err != nil {
		os.Remove(path)
		return "", err
	}
	return path, nil
}

func validateUploadFile(path string, maximum int64) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("файл %q недоступен: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%q не должен быть символической ссылкой", path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%q не является обычным файлом", path)
	}
	if info.Size() <= 0 || info.Size() > maximum {
		return fmt.Errorf("недопустимый размер файла %q", path)
	}
	return nil
}

func lastNonEmptyLine(value string) string {
	lines := strings.Split(strings.TrimSpace(value), "\n")
	for index := len(lines) - 1; index >= 0; index-- {
		if line := strings.TrimSpace(lines[index]); line != "" {
			return line
		}
	}
	return "unknown"
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func randomSuffix() (string, error) {
	value := make([]byte, 12)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func cleanupRemote(ctx context.Context, cfg config.AdminConfig, options Options, paths ...string) {
	parts := []string{"rm", "-f"}
	for _, path := range paths {
		if path != "" {
			parts = append(parts, path)
		}
	}
	_, _, _ = runRawSSH(ctx, cfg, options, remoteCommand(parts), 30*time.Second)
}
