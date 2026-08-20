package sshkey

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
)

const MaxPublicKeySize = 16 << 10

var usernamePattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// ValidateUsername accepts conservative Linux login names that are also safe
// to use as individual command arguments. System accounts and root are denied.
func ValidateUsername(username string) error {
	if username == "root" || !usernamePattern.MatchString(username) {
		return errors.New("имя пользователя должно содержать 1–32 символа: a-z, 0-9, _ или - и не может быть root")
	}
	return nil
}

// NormalizePublicKey validates one OpenSSH Ed25519 public-key line and returns
// a stable representation plus its OpenSSH-style SHA256 fingerprint.
func NormalizePublicKey(value string) (string, string, error) {
	line := strings.TrimSpace(value)
	if line == "" || len(line) > MaxPublicKeySize || strings.ContainsAny(line, "\r\n\x00") {
		return "", "", errors.New("публичный ключ должен занимать одну строку размером не более 16 KiB")
	}
	fields := strings.Fields(line)
	if len(fields) < 2 || fields[0] != "ssh-ed25519" {
		return "", "", errors.New("поддерживается только публичный ключ Ed25519 в формате OpenSSH")
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil || !validEd25519Blob(blob) {
		return "", "", errors.New("публичный ключ Ed25519 имеет некорректный формат")
	}
	digest := sha256.Sum256(blob)
	fingerprint := "SHA256:" + base64.RawStdEncoding.EncodeToString(digest[:])
	return strings.Join(fields, " "), fingerprint, nil
}

func ReadPublicKey(path string) (string, string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", "", fmt.Errorf("публичный ключ недоступен: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > MaxPublicKeySize {
		return "", "", errors.New("публичный ключ должен быть небольшим обычным файлом без symlink")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", "", err
	}
	return NormalizePublicKey(string(data))
}

func validEd25519Blob(blob []byte) bool {
	algorithm, rest, ok := readSSHString(blob)
	if !ok || string(algorithm) != "ssh-ed25519" {
		return false
	}
	key, rest, ok := readSSHString(rest)
	return ok && len(key) == 32 && len(rest) == 0
}

func readSSHString(data []byte) ([]byte, []byte, bool) {
	if len(data) < 4 {
		return nil, nil, false
	}
	size := uint64(binary.BigEndian.Uint32(data[:4]))
	if size > uint64(len(data)-4) {
		return nil, nil, false
	}
	end := 4 + int(size)
	return data[4:end], data[end:], true
}
