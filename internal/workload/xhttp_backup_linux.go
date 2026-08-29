//go:build linux

package workload

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func createXHTTPBackup(ctx context.Context, managedBefore bool) (backupState, error) {
	if err := ensureDirectoryPath(xhttpBackupRoot); err != nil {
		return backupState{}, err
	}
	directory, err := os.MkdirTemp(xhttpBackupRoot, time.Now().UTC().Format("20060102T150405.000000000Z")+"-")
	if err != nil {
		return backupState{}, err
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return backupState{}, err
	}
	state := backupState{Directory: directory, Existing: map[string]bool{}}
	if output, err := runCommand(ctx, "systemctl", "is-active", "x-ui.service"); err == nil && strings.TrimSpace(output) == "active" {
		state.WasActive = true
	}
	if output, err := runCommand(ctx, "systemctl", "is-enabled", "x-ui.service"); err == nil && strings.TrimSpace(output) == "enabled" {
		state.WasEnabled = true
	}
	if !managedBefore {
		return state, nil
	}
	for _, source := range managedXHTTPPaths {
		if _, err := os.Lstat(source); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return backupState{}, err
		}
		state.Existing[source] = true
		destination := filepath.Join(directory, "rootfs", strings.TrimPrefix(source, "/"))
		if err := copyPath(source, destination); err != nil {
			return backupState{}, err
		}
	}
	return state, nil
}

func ensurePrivateWorkloadDirectory() error {
	directory := filepath.Dir(XHTTPMarkerPath)
	if err := ensureDirectoryPath(directory); err != nil {
		return err
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return err
	}
	if err := os.Chown(directory, 0, 0); err != nil {
		return err
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return err
	}
	stat, owned := info.Sys().(*syscall.Stat_t)
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 || !owned || stat.Uid != 0 {
		return errors.New("каталог workload должен быть обычным каталогом с правами 0700")
	}
	return nil
}

func secureXUIState() error {
	for _, directory := range []string{xuiDatabaseRoot, xuiLogRoot} {
		if err := ensureDirectoryPath(directory); err != nil {
			return err
		}
		if err := os.Chown(directory, 0, 0); err != nil {
			return err
		}
		if err := os.Chmod(directory, 0o700); err != nil {
			return err
		}
	}
	info, err := os.Lstat(xuiDatabase)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("x-ui.db должен быть обычным файлом без symlink")
	}
	if err := os.Chown(xuiDatabase, 0, 0); err != nil {
		return err
	}
	if err := os.Chmod(xuiDatabase, 0o600); err != nil {
		return err
	}
	return verifyXUIStatePermissions()
}

func verifyXUIStatePermissions() error {
	for _, item := range []struct {
		path string
		mode fs.FileMode
		dir  bool
	}{
		{path: xuiDatabaseRoot, mode: 0o700, dir: true},
		{path: xuiLogRoot, mode: 0o700, dir: true},
		{path: xuiDatabase, mode: 0o600},
	} {
		info, err := os.Lstat(item.path)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || info.IsDir() != item.dir || info.Mode().Perm() != item.mode {
			return fmt.Errorf("%s имеет неверный тип или права %04o", item.path, info.Mode().Perm())
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || stat.Gid != 0 {
			return fmt.Errorf("%s должен принадлежать root:root", item.path)
		}
	}
	environment, err := readRegularFile(xuiEnvironment, 64*1024)
	if err != nil {
		return err
	}
	if string(environment) != xuiEnvironmentPolicy {
		return errors.New("environment x-ui не совпадает с управляемой SQLite-политикой")
	}
	info, err := os.Lstat(xuiEnvironment)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if info.Mode().Perm() != 0o600 || !ok || stat.Uid != 0 || stat.Gid != 0 {
		return errors.New("environment x-ui должен принадлежать root:root с правами 0600")
	}
	return nil
}

func restoreXHTTPBackup(ctx context.Context, backup backupState) error {
	var rollbackErr error
	if output, err := runCommand(ctx, "systemctl", "stop", "x-ui.service"); err != nil && !missingSystemdUnit(output) {
		rollbackErr = errors.Join(rollbackErr, fmt.Errorf("остановить x-ui: %w (%s)", err, output))
	}
	if output, err := runCommand(ctx, "systemctl", "disable", "x-ui.service"); err != nil && !missingSystemdUnit(output) {
		rollbackErr = errors.Join(rollbackErr, fmt.Errorf("отключить x-ui: %w (%s)", err, output))
	}
	for _, path := range managedXHTTPPaths {
		if err := removeManagedPath(path); err != nil {
			rollbackErr = errors.Join(rollbackErr, err)
			continue
		}
		if backup.Existing[path] {
			source := filepath.Join(backup.Directory, "rootfs", strings.TrimPrefix(path, "/"))
			if err := copyPath(source, path); err != nil {
				rollbackErr = errors.Join(rollbackErr, err)
			}
		}
	}
	if output, err := runCommand(ctx, "systemctl", "daemon-reload"); err != nil {
		rollbackErr = errors.Join(rollbackErr, fmt.Errorf("systemd daemon-reload: %w (%s)", err, output))
	}
	if backup.WasEnabled {
		if output, err := runCommand(ctx, "systemctl", "enable", "x-ui.service"); err != nil {
			rollbackErr = errors.Join(rollbackErr, fmt.Errorf("восстановить enable x-ui: %w (%s)", err, output))
		}
	}
	if backup.WasActive {
		if output, err := runCommand(ctx, "systemctl", "start", "x-ui.service"); err != nil {
			rollbackErr = errors.Join(rollbackErr, fmt.Errorf("восстановить active x-ui: %w (%s)", err, output))
		}
	}
	return rollbackErr
}

func missingSystemdUnit(output string) bool {
	value := strings.ToLower(output)
	return strings.Contains(value, "not loaded") || strings.Contains(value, "not found") || strings.Contains(value, "could not be found")
}

func copyPath(source, destination string) error {
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("backup отклоняет symlink %s", source)
	}
	if info.Mode().IsRegular() {
		return atomicCopyFile(source, destination, info.Mode().Perm())
	}
	if !info.IsDir() {
		return fmt.Errorf("backup отклоняет специальный файл %s", source)
	}
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		entryInfo, err := entry.Info()
		if err != nil {
			return err
		}
		if entryInfo.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("backup отклоняет symlink %s", path)
		}
		if entry.IsDir() {
			return os.MkdirAll(target, entryInfo.Mode().Perm())
		}
		if !entryInfo.Mode().IsRegular() {
			return fmt.Errorf("backup отклоняет специальный файл %s", path)
		}
		return atomicCopyFile(path, target, entryInfo.Mode().Perm())
	})
}

func atomicCopyFile(source, destination string, mode fs.FileMode) error {
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > 2<<30 {
		return fmt.Errorf("небезопасный или слишком большой исходный файл: %s", source)
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	directory := filepath.Dir(destination)
	if err := ensureDirectoryPath(directory); err != nil {
		return err
	}
	if targetInfo, statErr := os.Lstat(destination); statErr == nil && targetInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("destination является symlink: %s", destination)
	} else if statErr != nil && !os.IsNotExist(statErr) {
		return statErr
	}
	output, err := os.CreateTemp(directory, ".bastionctl-copy-")
	if err != nil {
		return err
	}
	temporary := output.Name()
	defer os.Remove(temporary)
	if err := output.Chmod(mode); err != nil {
		output.Close()
		return err
	}
	copied, copyErr := io.Copy(output, io.LimitReader(input, info.Size()+1))
	if copyErr != nil || copied != info.Size() {
		output.Close()
		return errors.Join(copyErr, errors.New("исходный файл изменился или скопирован не полностью"))
	}
	if err := output.Sync(); err != nil {
		output.Close()
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, destination); err != nil {
		return err
	}
	return syncDirectory(directory)
}

func atomicWriteFile(path string, data []byte, mode fs.FileMode) error {
	directory := filepath.Dir(path)
	if err := ensureDirectoryPath(directory); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("destination является symlink: %s", path)
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	file, err := os.CreateTemp(directory, ".bastionctl-write-")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(mode); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	return syncDirectory(directory)
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func ensureDirectoryPath(path string) error {
	clean := filepath.Clean(path)
	if clean == "." || !filepath.IsAbs(clean) {
		return errors.New("требуется абсолютный каталог")
	}
	current := string(filepath.Separator)
	for _, component := range strings.Split(strings.TrimPrefix(clean, string(filepath.Separator)), string(filepath.Separator)) {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			if err := os.Mkdir(current, 0o755); err != nil && !os.IsExist(err) {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("небезопасный компонент каталога: %s", current)
		}
	}
	return nil
}

func readRegularFile(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > maximum {
		return nil, fmt.Errorf("небезопасный или слишком большой файл: %s", path)
	}
	return os.ReadFile(path)
}

func removeManagedPath(path string) error {
	allowed := false
	for _, candidate := range managedXHTTPPaths {
		if path == candidate {
			allowed = true
			break
		}
	}
	if !allowed {
		return fmt.Errorf("отказ удалять неуправляемый путь %s", path)
	}
	return os.RemoveAll(path)
}

func existingPaths(paths ...string) []string {
	result := []string{}
	for _, path := range paths {
		if _, err := os.Lstat(path); err == nil {
			result = append(result, path)
		} else if !os.IsNotExist(err) {
			result = append(result, path+"(?)")
		}
	}
	return result
}

func pathWithin(root, candidate string) bool {
	root = filepath.Clean(root)
	candidate = filepath.Clean(candidate)
	relative, err := filepath.Rel(root, candidate)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func listTCPListeners(ctx context.Context) ([]tcpListener, error) {
	output, err := runCommand(ctx, "ss", "-H", "-ltnp")
	if err != nil {
		return nil, err
	}
	return parseTCPListeners(output), nil
}

func parseTCPListeners(output string) []tcpListener {
	result := []tcpListener{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		address, port, ok := splitListenerAddress(fields[3])
		if ok {
			owner := ""
			if len(fields) > 5 {
				owner = strings.Join(fields[5:], " ")
			}
			result = append(result, tcpListener{Address: address, Port: port, Owner: owner})
		}
	}
	return result
}

func splitListenerAddress(value string) (string, int, bool) {
	index := strings.LastIndex(value, ":")
	if index < 0 || index == len(value)-1 {
		return "", 0, false
	}
	port, err := strconv.Atoi(value[index+1:])
	if err != nil || port < 1 || port > 65535 {
		return "", 0, false
	}
	address := strings.Trim(value[:index], "[]")
	if percent := strings.LastIndex(address, "%"); percent >= 0 {
		address = address[:percent]
	}
	return address, port, true
}

func listenersOnPort(listeners []tcpListener, port int) []tcpListener {
	result := []tcpListener{}
	for _, listener := range listeners {
		if listener.Port == port {
			result = append(result, listener)
		}
	}
	return result
}

func listenerOwnedBy(listener tcpListener, fragment string) bool {
	return strings.Contains(strings.ToLower(listener.Owner), strings.ToLower(fragment))
}

func isLoopbackAddress(value string) bool {
	if value == "localhost" {
		return true
	}
	ip := net.ParseIP(value)
	return ip != nil && ip.IsLoopback()
}

func parseUFWState(output string, panelPort int) ufwState {
	state := ufwState{}
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(strings.ToLower(raw))
		if strings.HasPrefix(line, "status:") && strings.Contains(line, "active") && !strings.Contains(line, "inactive") {
			state.Active = true
		}
		if strings.HasPrefix(line, "default:") && (strings.Contains(line, "deny (incoming)") || strings.Contains(line, "reject (incoming)")) {
			state.DenyIncoming = true
		}
		line = strings.ReplaceAll(line, " (v6)", "")
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.HasPrefix(fields[1], "allow") {
			continue
		}
		rule := fields[0]
		publicSource := len(fields) >= 4 && fields[3] == "anywhere"
		if rule == "80/tcp" && publicSource {
			state.Allow80 = true
		}
		if rule == "443/tcp" && publicSource {
			state.Allow443 = true
		}
		if ufwRuleIncludesPort(rule, panelPort) {
			state.PanelExposed = true
		}
	}
	return state
}

func ufwRuleIncludesPort(rule string, port int) bool {
	rule = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(rule)), "/tcp")
	if rule == "anywhere" || rule == strconv.Itoa(port) {
		return true
	}
	first, last, ranged := strings.Cut(rule, ":")
	if !ranged {
		return false
	}
	start, startErr := strconv.Atoi(first)
	end, endErr := strconv.Atoi(last)
	return startErr == nil && endErr == nil && start <= port && port <= end
}
