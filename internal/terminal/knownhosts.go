package terminal

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

var errHostKeyCaptured = errors.New("host key captured")

type HostKeyInfo struct {
	Target      string `json:"target"`
	Address     string `json:"address"`
	Algorithm   string `json:"algorithm"`
	Fingerprint string `json:"fingerprint"`
	Trusted     bool   `json:"trusted"`
}

func ProbeHostKey(ctx context.Context, target string, port int, timeout time.Duration) (HostKeyInfo, ssh.PublicKey, error) {
	user, host, err := splitTarget(target)
	if err != nil {
		return HostKeyInfo{}, nil, err
	}
	address := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	var captured ssh.PublicKey
	config := secureClientConfig(user, nil, func(_ string, _ net.Addr, key ssh.PublicKey) error {
		captured = key
		return errHostKeyCaptured
	}, timeout)
	connection, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", address)
	if err != nil {
		return HostKeyInfo{}, nil, fmt.Errorf("подключиться к SSH для чтения host key: %w", err)
	}
	defer connection.Close()
	_, _, _, handshakeErr := ssh.NewClientConn(connection, address, config)
	if captured == nil {
		if handshakeErr == nil {
			return HostKeyInfo{}, nil, errors.New("SSH-сервер не предоставил host key")
		}
		return HostKeyInfo{}, nil, fmt.Errorf("получить SSH host key: %w", handshakeErr)
	}
	return HostKeyInfo{
		Target: target, Address: knownhosts.Normalize(address), Algorithm: captured.Type(),
		Fingerprint: ssh.FingerprintSHA256(captured),
	}, captured, nil
}

func TrustHostKey(ctx context.Context, target string, port int, path, observed, confirmation string, timeout time.Duration) (HostKeyInfo, error) {
	if strings.TrimSpace(path) == "" {
		return HostKeyInfo{}, errors.New("путь хранилища host key отсутствует")
	}
	info, key, err := ProbeHostKey(ctx, target, port, timeout)
	if err != nil {
		return HostKeyInfo{}, err
	}
	if observed == "" || info.Fingerprint != observed {
		return HostKeyInfo{}, errors.New("SSH host key изменился после показа fingerprint; доверие не сохранено")
	}
	if confirmation != "TRUST "+info.Fingerprint {
		return HostKeyInfo{}, errors.New("для закрепления введите точную строку TRUST <fingerprint>")
	}
	line := knownhosts.Line([]string{info.Address}, key) + "\n"
	if err := atomicWriteKnownHost(path, []byte(line)); err != nil {
		return HostKeyInfo{}, err
	}
	info.Trusted = true
	return info, nil
}

func ReplaceHostKey(ctx context.Context, target string, port int, path, observed, confirmation string, timeout time.Duration) (HostKeyInfo, error) {
	if !HasPinnedHostKey(path) {
		return HostKeyInfo{}, errors.New("предыдущий SSH host key отсутствует; используйте обычное закрепление")
	}
	info, key, err := ProbeHostKey(ctx, target, port, timeout)
	if err != nil {
		return HostKeyInfo{}, err
	}
	if observed == "" || info.Fingerprint != observed {
		return HostKeyInfo{}, errors.New("SSH host key изменился после показа fingerprint; замена не выполнена")
	}
	if confirmation != "REPLACE "+info.Fingerprint {
		return HostKeyInfo{}, errors.New("для замены введите точную строку REPLACE <fingerprint>")
	}
	previous, err := os.ReadFile(path)
	if err != nil {
		return HostKeyInfo{}, err
	}
	if err := atomicWriteKnownHost(path+".previous", previous); err != nil {
		return HostKeyInfo{}, fmt.Errorf("сохранить предыдущий host key: %w", err)
	}
	line := knownhosts.Line([]string{info.Address}, key) + "\n"
	if err := atomicWriteKnownHost(path, []byte(line)); err != nil {
		return HostKeyInfo{}, err
	}
	info.Trusted = true
	return info, nil
}

func PinnedHostKeyCallback(path string) (ssh.HostKeyCallback, error) {
	file, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.New("SSH host key ещё не закреплён; сначала сверьте fingerprint")
		}
		return nil, err
	}
	if file.Mode()&os.ModeSymlink != 0 || !file.Mode().IsRegular() || file.Size() < 1 || file.Size() > 64*1024 {
		return nil, errors.New("файл закреплённого SSH host key имеет небезопасный тип или размер")
	}
	return knownhosts.New(path)
}

func HasPinnedHostKey(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode()&os.ModeSymlink == 0 && info.Mode().IsRegular() && info.Size() > 0 && info.Size() <= 64*1024
}

func atomicWriteKnownHost(path string, data []byte) error {
	directory := filepath.Dir(path)
	if info, err := os.Lstat(directory); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.New("каталог host key должен быть обычным каталогом без symlink")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	_ = os.Chmod(directory, 0o700)
	temporary, err := os.CreateTemp(directory, ".known-host-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	success := false
	defer func() {
		_ = temporary.Close()
		if !success {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	if directoryHandle, err := os.Open(directory); err == nil {
		_ = directoryHandle.Sync()
		_ = directoryHandle.Close()
	}
	success = true
	return nil
}
