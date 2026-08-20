//go:build linux

package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type commandResult struct {
	Stdout string
	Stderr string
	Err    error
}

func runCommand(ctx context.Context, stdin string, name string, args ...string) commandResult {
	path, err := findCommand(name)
	if err != nil {
		return commandResult{Err: err}
	}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C", "DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=a")
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	return commandResult{Stdout: strings.TrimSpace(stdout.String()), Stderr: strings.TrimSpace(stderr.String()), Err: err}
}

func findCommand(name string) (string, error) {
	if strings.ContainsRune(name, '/') {
		if info, err := os.Stat(name); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return name, nil
		}
		return "", fmt.Errorf("команда %s недоступна", name)
	}
	if path, err := exec.LookPath(name); err == nil {
		return path, nil
	}
	for _, directory := range []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
		path := filepath.Join(directory, name)
		if info, err := os.Stat(path); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return path, nil
		}
	}
	return "", fmt.Errorf("команда %s не найдена", name)
}

type processLock struct {
	file *os.File
}

func acquireLock() (*processLock, error) {
	file, err := os.OpenFile("/run/lock/bastionctl.lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("открыть lock-файл: %w", err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, errors.New("другой процесс bastionctl уже выполняет apply")
	}
	if err := file.Truncate(0); err == nil {
		_, _ = fmt.Fprintf(file, "%d\n", os.Getpid())
		_ = file.Sync()
	}
	return &processLock{file: file}, nil
}

func (lock *processLock) Close() {
	if lock == nil || lock.file == nil {
		return
	}
	_ = syscall.Flock(int(lock.file.Fd()), syscall.LOCK_UN)
	_ = lock.file.Close()
}

type fileSnapshot struct {
	path       string
	backupPath string
	existed    bool
	mode       os.FileMode
	uid        int
	gid        int
}

func snapshotFile(path, backupRoot, control string) (*fileSnapshot, error) {
	snapshot := &fileSnapshot{path: path, uid: 0, gid: 0}
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return snapshot, nil
		}
		return nil, fmt.Errorf("lstat %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s является символической ссылкой; автоматическая запись запрещена", path)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s не является обычным файлом", path)
	}
	snapshot.existed = true
	snapshot.mode = info.Mode().Perm()
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		snapshot.uid = int(stat.Uid)
		snapshot.gid = int(stat.Gid)
	}
	backupDirectory := filepath.Join(backupRoot, sanitizeName(control))
	if err := os.MkdirAll(backupDirectory, 0o700); err != nil {
		return nil, fmt.Errorf("создать каталог резервной копии: %w", err)
	}
	snapshot.backupPath = filepath.Join(backupDirectory, sanitizeName(strings.TrimPrefix(path, "/"))+".bak")
	if err := copyFile(path, snapshot.backupPath, 0o600); err != nil {
		return nil, fmt.Errorf("резервная копия %s: %w", path, err)
	}
	return snapshot, nil
}

func (snapshot *fileSnapshot) Write(content []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(snapshot.path), 0o755); err != nil {
		return fmt.Errorf("создать каталог %s: %w", filepath.Dir(snapshot.path), err)
	}
	uid, gid := 0, 0
	if snapshot.existed {
		uid, gid = snapshot.uid, snapshot.gid
	}
	return atomicWrite(snapshot.path, content, mode, uid, gid)
}

func (snapshot *fileSnapshot) Restore() error {
	if !snapshot.existed {
		if err := os.Remove(snapshot.path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("удалить новый файл %s: %w", snapshot.path, err)
		}
		return syncDirectory(filepath.Dir(snapshot.path))
	}
	content, err := os.ReadFile(snapshot.backupPath)
	if err != nil {
		return fmt.Errorf("прочитать резервную копию: %w", err)
	}
	return atomicWrite(snapshot.path, content, snapshot.mode, snapshot.uid, snapshot.gid)
}

func atomicWrite(path string, content []byte, mode os.FileMode, uid, gid int) (resultErr error) {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".bastionctl-*")
	if err != nil {
		return fmt.Errorf("создать временный файл: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		if resultErr != nil {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(mode); err != nil {
		return fmt.Errorf("установить права временного файла: %w", err)
	}
	if err := temporary.Chown(uid, gid); err != nil {
		return fmt.Errorf("установить владельца временного файла: %w", err)
	}
	if _, err := temporary.Write(content); err != nil {
		return fmt.Errorf("записать временный файл: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("синхронизировать временный файл: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("закрыть временный файл: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("атомарно заменить %s: %w", path, err)
	}
	return syncDirectory(directory)
}

func copyFile(source, destination string, mode os.FileMode) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	completed := false
	defer func() {
		_ = output.Close()
		if !completed {
			_ = os.Remove(destination)
		}
	}()
	if _, err := io.Copy(output, input); err != nil {
		return err
	}
	if err := output.Sync(); err != nil {
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	completed = true
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func sanitizeName(value string) string {
	value = strings.TrimSpace(value)
	var builder strings.Builder
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-' || char == '_' || char == '.' {
			builder.WriteRune(char)
		} else {
			builder.WriteByte('_')
		}
	}
	if builder.Len() == 0 {
		return "file"
	}
	return builder.String()
}

func newBackupRoot() (string, error) {
	name := time.Now().UTC().Format("20060102T150405Z") + "-" + strconv.Itoa(os.Getpid())
	path := filepath.Join("/var/backups/bastionctl", name)
	if err := os.MkdirAll(path, 0o700); err != nil {
		return "", err
	}
	return path, nil
}

func preflightManagedPath(path string) error {
	if err := rejectSymlinkParents(filepath.Dir(path)); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			parent := filepath.Dir(path)
			if parentInfo, parentErr := os.Stat(parent); parentErr == nil && parentInfo.IsDir() {
				return nil
			}
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("целевой файл является символической ссылкой")
	}
	if !info.Mode().IsRegular() {
		return errors.New("целевой путь не является обычным файлом")
	}
	return nil
}

func rejectSymlinkParents(path string) error {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return errors.New("управляемый путь должен быть абсолютным")
	}
	current := string(filepath.Separator)
	for _, component := range strings.Split(strings.TrimPrefix(clean, string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return fmt.Errorf("проверить компонент %s: %w", current, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("родительский компонент %s является символической ссылкой", current)
		}
		if !info.IsDir() {
			return fmt.Errorf("родительский компонент %s не является каталогом", current)
		}
	}
	return nil
}

func boolWord(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

func firstError(result commandResult) string {
	if result.Stderr != "" {
		return result.Stderr
	}
	if result.Stdout != "" {
		return result.Stdout
	}
	if result.Err != nil {
		return result.Err.Error()
	}
	return "неизвестная ошибка"
}

func limitText(value string, maximum int) string {
	if len(value) <= maximum {
		return value
	}
	return value[:maximum] + "…"
}
