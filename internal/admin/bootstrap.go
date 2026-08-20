package admin

import (
	"context"
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
	"bastionctl/internal/sshkey"
)

type BootstrapOptions struct {
	Login         Options
	ManagedTarget string
	PublicKeyPath string
	Input         io.Reader
	Output        io.Writer
}

func ValidateBootstrapUsername(username string) error {
	return sshkey.ValidateUsername(username)
}

func GenerateIdentity(ctx context.Context, path, comment string) error {
	if strings.ContainsAny(comment, "\r\n\x00") {
		return errors.New("комментарий SSH-ключа содержит недопустимые символы")
	}
	directory := filepath.Dir(path)
	info, err := os.Lstat(directory)
	if err != nil {
		return fmt.Errorf("каталог SSH-ключа недоступен: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("каталог SSH-ключа должен быть обычным каталогом без symlink")
	}
	for _, candidate := range []string{path, path + ".pub"} {
		if _, err := os.Lstat(candidate); err == nil {
			return fmt.Errorf("файл SSH-ключа уже существует: %s", candidate)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		return errors.New("ssh-keygen не найден в PATH; установите OpenSSH Client")
	}
	commandCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(commandCtx, keygen,
		"-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", path,
	)
	output, commandErr := cmd.CombinedOutput()
	if commandErr != nil {
		_ = os.Remove(path)
		_ = os.Remove(path + ".pub")
		if errors.Is(commandCtx.Err(), context.DeadlineExceeded) {
			return errors.New("ssh-keygen превысил таймаут")
		}
		message := strings.TrimSpace(string(output))
		if message == "" {
			message = commandErr.Error()
		}
		return fmt.Errorf("создать SSH-ключ: %s", limit(message, 2000))
	}
	if err := validateGeneratedPrivateKey(path); err != nil {
		_ = os.Remove(path)
		_ = os.Remove(path + ".pub")
		return err
	}
	if _, err := ReadPublicKey(path + ".pub"); err != nil {
		_ = os.Remove(path)
		_ = os.Remove(path + ".pub")
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = os.Remove(path)
		_ = os.Remove(path + ".pub")
		return err
	}
	_ = os.Chmod(path+".pub", 0o644)
	return nil
}

func ReadPublicKey(path string) (string, error) {
	value, _, err := sshkey.ReadPublicKey(path)
	return value, err
}

func NormalizePublicKey(value string) (string, string, error) {
	return sshkey.NormalizePublicKey(value)
}

func BootstrapKey(ctx context.Context, cfg config.AdminConfig, options BootstrapOptions) error {
	if err := validateConnection(options.Login); err != nil {
		return err
	}
	if err := ValidateTarget(options.ManagedTarget); err != nil {
		return fmt.Errorf("цель управления: %w", err)
	}
	if err := requireTerminal(options.Input); err != nil {
		return err
	}
	loginUser, loginHost := splitTarget(options.Login.Target)
	managedUser, managedHost := splitTarget(options.ManagedTarget)
	if loginHost != managedHost {
		return errors.New("первичный и постоянный SSH-доступ должны вести на один хост")
	}
	if managedUser == "root" {
		return errors.New("постоянное управление от root запрещено; укажите непривилегированного администратора")
	}
	if loginUser == "root" {
		if err := ValidateBootstrapUsername(managedUser); err != nil {
			return err
		}
	}
	if loginUser != "root" && loginUser != managedUser {
		return errors.New("создать другого администратора можно только при первичном входе от root")
	}
	publicKey, err := ReadPublicKey(options.PublicKeyPath)
	if err != nil {
		return err
	}
	command := bootstrapAuthorizedKeyCommand(loginUser, managedUser, publicKey)
	if err := runPasswordSSH(ctx, cfg, options.Login, command, options.Input, options.Output); err != nil {
		return err
	}
	connection := options.Login
	connection.Target = options.ManagedTarget
	strictCfg := cfg
	strictCfg.StrictHostKeyChecking = true
	stdout, stderr, err := runRawSSH(ctx, strictCfg, connection, "printf '%s\\n' 'bastionctl-key-ok'", 45*time.Second)
	if err != nil || strings.TrimSpace(string(stdout)) != "bastionctl-key-ok" {
		message := strings.TrimSpace(string(stderr))
		if message == "" && err != nil {
			message = err.Error()
		}
		if message == "" {
			message = "сервер не подтвердил тестовую строку"
		}
		return fmt.Errorf("ключ установлен, но проверочный вход не удался: %s", limit(message, 2000))
	}
	return nil
}

func runPasswordSSH(ctx context.Context, cfg config.AdminConfig, options Options, command string, input io.Reader, output io.Writer) error {
	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		return errors.New("OpenSSH Client не найден в PATH")
	}
	strict := "yes"
	if !cfg.StrictHostKeyChecking {
		strict = "ask"
	}
	args := []string{
		"-tt",
		"-o", "BatchMode=no",
		"-o", "PubkeyAuthentication=no",
		"-o", "PreferredAuthentications=keyboard-interactive,password",
		"-o", "PasswordAuthentication=yes",
		"-o", "KbdInteractiveAuthentication=yes",
		"-o", "NumberOfPasswordPrompts=3",
		"-o", "ConnectTimeout=" + strconv.Itoa(cfg.ConnectTimeout),
		"-o", "ServerAliveInterval=15",
		"-o", "ServerAliveCountMax=3",
		"-o", "StrictHostKeyChecking=" + strict,
		"-p", strconv.Itoa(options.Port),
		"--", options.Target, command,
	}
	commandCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(commandCtx, sshPath, args...)
	cmd.Stdin = input
	if output == nil {
		output = io.Discard
	}
	cmd.Stdout = output
	cmd.Stderr = output
	if err := cmd.Run(); err != nil {
		if errors.Is(commandCtx.Err(), context.DeadlineExceeded) {
			return errors.New("первичный SSH-вход превысил таймаут")
		}
		return fmt.Errorf("первичный SSH-вход завершился с ошибкой: %w", err)
	}
	return nil
}

func bootstrapAuthorizedKeyCommand(loginUser, managedUser, publicKey string) string {
	key := shellQuote(publicKey)
	if loginUser != "root" {
		return "set -eu; sshdir=\"$HOME/.ssh\"; keyfile=\"$sshdir/authorized_keys\"; " +
			"[ ! -L \"$sshdir\" ] || { printf '%s\\n' 'bastionctl: ~/.ssh is a symlink' >&2; exit 73; }; " +
			"mkdir -p \"$sshdir\"; [ -d \"$sshdir\" ]; [ \"$(stat -c %u \"$sshdir\")\" = \"$(id -u)\" ]; chmod 700 \"$sshdir\"; " +
			"[ ! -L \"$keyfile\" ] || { printf '%s\\n' 'bastionctl: authorized_keys is a symlink' >&2; exit 73; }; " +
			"touch \"$keyfile\"; [ -f \"$keyfile\" ]; [ \"$(stat -c %u \"$keyfile\")\" = \"$(id -u)\" ]; chmod 600 \"$keyfile\"; " +
			"grep -qxF -- " + key + " \"$keyfile\" || printf '%s\\n' " + key + " >> \"$keyfile\""
	}
	user := shellQuote(managedUser)
	return "set -eu; managed_user=" + user + "; " +
		"if ! command -v sudo >/dev/null 2>&1 || ! getent group sudo >/dev/null 2>&1; then command -v apt-get >/dev/null || { printf '%s\\n' 'bastionctl: sudo is missing and apt-get is unavailable' >&2; exit 69; }; printf '%s\\n' 'bastionctl: installing sudo from configured repositories'; apt-get update; DEBIAN_FRONTEND=noninteractive apt-get install -y sudo; fi; " +
		"if ! id \"$managed_user\" >/dev/null 2>&1; then command -v useradd >/dev/null; useradd --create-home --shell /bin/bash \"$managed_user\"; fi; " +
		"managed_uid=$(id -u \"$managed_user\"); [ \"$managed_uid\" -ge 1000 ] || { printf '%s\\n' 'bastionctl: refusing a system or UID-0 account' >&2; exit 77; }; getent group sudo >/dev/null; usermod -aG sudo \"$managed_user\"; " +
		"managed_home=$(getent passwd \"$managed_user\" | awk -F: 'NR == 1 { print $6 }'); managed_shell=$(getent passwd \"$managed_user\" | awk -F: 'NR == 1 { print $7 }'); case \"$managed_home\" in /*) ;; *) printf '%s\\n' 'bastionctl: administrator home is not absolute' >&2; exit 77 ;; esac; [ \"$managed_home\" != / ]; case \"$managed_shell\" in *nologin|*false) printf '%s\\n' 'bastionctl: administrator has a non-login shell' >&2; exit 77 ;; esac; managed_group=$(id -gn \"$managed_user\"); " +
		"sshdir=\"$managed_home/.ssh\"; keyfile=\"$sshdir/authorized_keys\"; [ ! -L \"$sshdir\" ] || { printf '%s\\n' 'bastionctl: .ssh is a symlink' >&2; exit 73; }; " +
		"install -d -m 0700 -o \"$managed_user\" -g \"$managed_group\" \"$sshdir\"; [ ! -L \"$keyfile\" ] || { printf '%s\\n' 'bastionctl: authorized_keys is a symlink' >&2; exit 73; }; " +
		"touch \"$keyfile\"; [ -f \"$keyfile\" ]; chown \"$managed_user:$managed_group\" \"$keyfile\"; chmod 600 \"$keyfile\"; " +
		"grep -qxF -- " + key + " \"$keyfile\" || printf '%s\\n' " + key + " >> \"$keyfile\"; " +
		"password_state=$(passwd -S \"$managed_user\" | awk 'NR == 1 { print $2 }'); " +
		"if [ \"$password_state\" = L ] || [ \"$password_state\" = NP ]; then printf '%s\\n' 'Set a sudo password for the new administrator:'; passwd \"$managed_user\"; fi"
}

func validateGeneratedPrivateKey(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("закрытый ключ не создан: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 1<<20 {
		return errors.New("ssh-keygen создал недопустимый файл закрытого ключа")
	}
	return nil
}

func requireTerminal(input io.Reader) error {
	file, ok := input.(*os.File)
	if !ok {
		return errors.New("первичный вход требует интерактивный терминал; перенаправленный ввод запрещён")
	}
	info, err := file.Stat()
	if err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return errors.New("первичный вход требует интерактивный терминал; перенаправленный ввод запрещён")
	}
	return nil
}

func splitTarget(target string) (string, string) {
	separator := strings.LastIndex(target, "@")
	return target[:separator], target[separator+1:]
}
