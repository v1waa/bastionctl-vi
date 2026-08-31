package admin

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"bastionctl/internal/config"
)

type InstallUpload struct {
	Local  string `json:"local"`
	Remote string `json:"remote"`
	Data   []byte `json:"-"`
}

type PreparedInstall struct {
	Architecture  string          `json:"architecture"`
	PayloadName   string          `json:"payload_name"`
	PayloadSHA256 string          `json:"payload_sha256"`
	PayloadSize   int64           `json:"payload_size"`
	Uploads       []InstallUpload `json:"uploads"`
	Command       string          `json:"command"`
	RemotePaths   []string        `json:"remote_paths"`
	InstallSudo   bool            `json:"install_sudo"`
	localSudoers  string
}

func PrepareInstall(cfg config.AdminConfig, target, binaryPath, configPath, architecture string, installSudo, interactiveSudo bool) (*PreparedInstall, error) {
	if err := ValidateTarget(target); err != nil {
		return nil, err
	}
	if architecture != "amd64" && architecture != "arm64" {
		return nil, fmt.Errorf("неподдерживаемая архитектура сервера %q", architecture)
	}
	localArch, err := ELFArchitecture(binaryPath)
	if err != nil {
		return nil, fmt.Errorf("проверить серверный бинарник: %w", err)
	}
	if localArch != architecture {
		return nil, fmt.Errorf("выбран бинарник %s, а сервер использует %s", localArch, architecture)
	}
	binaryDigest, err := fileSHA256(binaryPath)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(binaryPath)
	if err != nil {
		return nil, err
	}
	return prepareInstall(cfg, target, InstallUpload{Local: binaryPath}, filepath.Base(binaryPath), binaryDigest, info.Size(), configPath, architecture, installSudo, interactiveSudo)
}

// PrepareInstallPayload creates the same transactional install plan as the
// file-based compatibility path, but keeps an embedded server binary in
// memory so the Windows application remains a single executable.
func PrepareInstallPayload(cfg config.AdminConfig, target, payloadName string, payload []byte, configPath, architecture string, installSudo, interactiveSudo bool) (*PreparedInstall, error) {
	if len(payload) == 0 || len(payload) > 100<<20 {
		return nil, errors.New("встроенный серверный компонент имеет недопустимый размер")
	}
	localArch, err := ELFArchitectureData(payload)
	if err != nil {
		return nil, fmt.Errorf("проверить встроенный серверный компонент: %w", err)
	}
	if localArch != architecture {
		return nil, fmt.Errorf("встроен компонент %s, а сервер использует %s", localArch, architecture)
	}
	digest := sha256.Sum256(payload)
	return prepareInstall(cfg, target, InstallUpload{Data: payload}, filepath.Base(payloadName), hex.EncodeToString(digest[:]), int64(len(payload)), configPath, architecture, installSudo, interactiveSudo)
}

func prepareInstall(cfg config.AdminConfig, target string, binaryUpload InstallUpload, payloadName, binaryDigest string, payloadSize int64, configPath, architecture string, installSudo, interactiveSudo bool) (*PreparedInstall, error) {
	if err := ValidateTarget(target); err != nil {
		return nil, err
	}
	if architecture != "amd64" && architecture != "arm64" {
		return nil, fmt.Errorf("неподдерживаемая архитектура сервера %q", architecture)
	}
	if err := validateUploadFile(configPath, 2<<20); err != nil {
		return nil, fmt.Errorf("проверить конфигурацию: %w", err)
	}
	suffix, err := randomSuffix()
	if err != nil {
		return nil, err
	}
	remoteBinary := "/tmp/bastionctl-bin-" + suffix
	remoteConfig := "/tmp/bastionctl-config-" + suffix
	remoteSudoers := "/tmp/bastionctl-sudoers-" + suffix
	backupBinary := "/tmp/bastionctl-old-bin-" + suffix
	backupConfig := "/tmp/bastionctl-old-config-" + suffix
	backupSudoers := "/tmp/bastionctl-old-sudoers-" + suffix
	prepared := &PreparedInstall{
		Architecture: architecture, PayloadName: payloadName, PayloadSHA256: binaryDigest, PayloadSize: payloadSize,
		Uploads: []InstallUpload{
			binaryUpload,
			{Local: configPath, Remote: remoteConfig},
		},
		RemotePaths: []string{remoteBinary, remoteConfig, remoteSudoers},
		InstallSudo: installSudo,
	}
	prepared.Uploads[0].Remote = remoteBinary
	if installSudo {
		prepared.localSudoers, err = createSudoersFile(target, cfg)
		if err != nil {
			return nil, err
		}
		prepared.Uploads = append(prepared.Uploads, InstallUpload{Local: prepared.localSudoers, Remote: remoteSudoers})
	}
	cleanupOnError := true
	defer func() {
		if cleanupOnError {
			prepared.Close()
		}
	}()
	configDigest, err := fileSHA256(configPath)
	if err != nil {
		return nil, err
	}
	sudo := "sudo -n"
	if interactiveSudo {
		sudo = "sudo"
	}
	commands := []string{
		"printf '%s  %s\\n' " + shellQuote(binaryDigest) + " " + shellQuote(remoteBinary) + " | sha256sum -c -",
		"printf '%s  %s\\n' " + shellQuote(configDigest) + " " + shellQuote(remoteConfig) + " | sha256sum -c -",
	}
	if prepared.localSudoers != "" {
		sudoDigest, digestErr := fileSHA256(prepared.localSudoers)
		if digestErr != nil {
			return nil, digestErr
		}
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
	if prepared.localSudoers != "" {
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
	if prepared.localSudoers != "" {
		prepare = append(prepare, "if "+sudo+" test -e /etc/sudoers.d/bastionctl; then "+sudo+" cp -p /etc/sudoers.d/bastionctl "+shellQuote(backupSudoers)+" && had_sudoers=1; fi")
		rollback = append(rollback, "if [ \"$had_sudoers\" -eq 1 ]; then "+sudo+" cp -p "+shellQuote(backupSudoers)+" /etc/sudoers.d/bastionctl; else "+sudo+" rm -f /etc/sudoers.d/bastionctl; fi")
	}
	prepare = append(prepare, "install_started=1")
	cleanupRoot := sudo + " rm -f " + shellQuote(backupBinary) + " " + shellQuote(backupConfig) + " " + shellQuote(backupSudoers)
	cleanupUser := "rm -f " + shellQuote(remoteBinary) + " " + shellQuote(remoteConfig) + " " + shellQuote(remoteSudoers)
	prepared.Command = "status=0; { " + strings.Join(prepare, " && ") + " && " + strings.Join(commands, " && ") +
		"; } || status=$?; if [ \"$status\" -ne 0 ] && [ \"$install_started\" -eq 1 ]; then if ! (" + strings.Join(rollback, " && ") +
		"); then printf '%s\\n' 'bastionctl: automatic install rollback failed' >&2; status=125; fi; fi; " +
		"if ! (" + cleanupRoot + " && " + cleanupUser + "); then printf '%s\\n' 'bastionctl: temporary file cleanup failed' >&2; status=125; fi; exit \"$status\""
	cleanupOnError = false
	return prepared, nil
}

func (p *PreparedInstall) Close() error {
	if p == nil || p.localSudoers == "" {
		return nil
	}
	path := p.localSudoers
	p.localSudoers = ""
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (p *PreparedInstall) CleanupCommand() (string, error) {
	if p == nil || len(p.RemotePaths) == 0 {
		return "", errors.New("план установки отсутствует")
	}
	parts := []string{"rm", "-f"}
	parts = append(parts, p.RemotePaths...)
	return remoteCommand(parts), nil
}
