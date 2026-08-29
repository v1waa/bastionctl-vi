package admin

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"bastionctl/internal/config"
	"bastionctl/internal/terminal"
)

func validateConnection(options Options) error {
	if err := ValidateTarget(options.Target); err != nil {
		return err
	}
	if options.Port < 1 || options.Port > 65535 {
		return errors.New("SSH-порт должен быть в диапазоне 1..65535")
	}
	if options.Embedded && options.KnownHostsFile == "" {
		return errors.New("встроенный SSH-транспорт требует закреплённый host key")
	}
	if options.Identity != "" {
		info, err := os.Lstat(options.Identity)
		if err != nil {
			return fmt.Errorf("закрытый ключ недоступен: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("путь закрытого ключа должен быть обычным файлом без symlink")
		}
	}
	if options.KnownHostsFile != "" {
		info, err := os.Lstat(options.KnownHostsFile)
		if err != nil {
			return fmt.Errorf("файл SSH host keys недоступен: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 64<<10 {
			return errors.New("файл SSH host keys должен быть непустым обычным файлом без symlink")
		}
	}
	return nil
}

func sshBaseArguments(cfg config.AdminConfig, options Options) []string {
	strict := "yes"
	if !cfg.StrictHostKeyChecking {
		strict = "accept-new"
	}
	args := []string{
		"-o", "BatchMode=yes",
		"-o", "PasswordAuthentication=no",
		"-o", "KbdInteractiveAuthentication=no",
		"-o", "NumberOfPasswordPrompts=0",
		"-o", "ConnectTimeout=" + strconv.Itoa(cfg.ConnectTimeout),
		"-o", "ServerAliveInterval=15",
		"-o", "ServerAliveCountMax=3",
		"-o", "StrictHostKeyChecking=" + strict,
		"-p", strconv.Itoa(options.Port),
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
	return args
}

func remoteCommand(parts []string) string {
	quoted := make([]string, len(parts))
	for index, part := range parts {
		quoted[index] = shellQuote(part)
	}
	return strings.Join(quoted, " ")
}

func runRawSSH(ctx context.Context, cfg config.AdminConfig, options Options, command string, timeout time.Duration) ([]byte, []byte, error) {
	return runRawSSHInput(ctx, cfg, options, command, nil, timeout)
}

func runRawSSHInput(ctx context.Context, cfg config.AdminConfig, options Options, command string, input io.Reader, timeout time.Duration) ([]byte, []byte, error) {
	if err := validateConnection(options); err != nil {
		return nil, nil, err
	}
	if options.Embedded {
		var payload []byte
		if input != nil {
			var err error
			payload, err = io.ReadAll(io.LimitReader(input, (2<<20)+1))
			if err != nil {
				return nil, nil, err
			}
			if len(payload) > 2<<20 {
				return nil, nil, errors.New("ввод удалённой команды слишком велик")
			}
		}
		commandCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		result, err := terminal.RunCommand(commandCtx, terminal.Connection{
			Target: options.Target, Port: options.Port, Identity: options.Identity,
			KnownHosts: options.KnownHostsFile, ConnectTimeout: time.Duration(cfg.ConnectTimeout) * time.Second,
		}, terminal.Credentials{Passphrase: options.Passphrase}, command, payload)
		return []byte(result.Stdout), []byte(result.Stderr), err
	}
	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		return nil, nil, errors.New("OpenSSH Client не найден в PATH")
	}
	args := sshBaseArguments(cfg, options)
	args = append(args, "--", options.Target, command)
	commandCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(commandCtx, sshPath, args...)
	cmd.Stdin = input
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	if errors.Is(commandCtx.Err(), context.DeadlineExceeded) {
		return stdout.Bytes(), stderr.Bytes(), context.DeadlineExceeded
	}
	return stdout.Bytes(), stderr.Bytes(), err
}

func runInteractiveSSH(ctx context.Context, cfg config.AdminConfig, options Options, command string, input io.Reader, output io.Writer, timeout time.Duration) ([]byte, []byte, error) {
	if err := validateConnection(options); err != nil {
		return nil, nil, err
	}
	if err := requireTerminal(input); err != nil {
		return nil, nil, err
	}
	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		return nil, nil, errors.New("OpenSSH Client не найден в PATH")
	}
	args := sshBaseArguments(cfg, options)
	args = append(args, "-tt", "--", options.Target, command)
	commandCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(commandCtx, sshPath, args...)
	cmd.Stdin = input
	var stdout, stderr bytes.Buffer
	if output == nil {
		output = io.Discard
	}
	cmd.Stdout = io.MultiWriter(output, &stdout)
	cmd.Stderr = io.MultiWriter(output, &stderr)
	err = cmd.Run()
	if errors.Is(commandCtx.Err(), context.DeadlineExceeded) {
		return stdout.Bytes(), stderr.Bytes(), context.DeadlineExceeded
	}
	return stdout.Bytes(), stderr.Bytes(), err
}
