package terminal

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
)

var remoteUploadPattern = regexp.MustCompile(`^/tmp/bastionctl-(?:bin|config|sudoers)-[0-9a-f]{24}$`)

func UploadFile(ctx context.Context, connection Connection, credentials Credentials, localPath, remotePath string, maximum int64) error {
	if !remoteUploadPattern.MatchString(remotePath) {
		return errors.New("удалённый путь загрузки не принадлежит безопасному временному пространству bastionctl")
	}
	info, err := os.Lstat(localPath)
	if err != nil {
		return fmt.Errorf("открыть файл загрузки: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 1 || maximum < 1 || info.Size() > maximum {
		return errors.New("файл загрузки имеет небезопасный тип или размер")
	}
	file, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer file.Close()
	client, err := Dial(ctx, connection, credentials)
	if err != nil {
		return err
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	session.Stdin = file
	stderr := &boundedBuffer{maximum: 64 << 10}
	session.Stderr = stderr
	command := "set -eu; umask 077; test ! -e " + quotePOSIX(remotePath) + "; cat > " + quotePOSIX(remotePath)
	done := make(chan error, 1)
	go func() { done <- session.Run(command) }()
	select {
	case err := <-done:
		if err != nil {
			message := strings.TrimSpace(stderr.String())
			if message == "" {
				message = err.Error()
			}
			return fmt.Errorf("загрузить файл: %s", message)
		}
		return nil
	case <-ctx.Done():
		_ = session.Close()
		_ = client.Close()
		<-done
		return ctx.Err()
	}
}

func quotePOSIX(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}
