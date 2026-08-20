//go:build linux

package server

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"bastionctl/internal/config"
	"bastionctl/internal/report"
	"bastionctl/internal/sshkey"
)

func createUserPlatform(ctx context.Context, _ config.Config, version string, request UserRequest) *report.Report {
	r := report.New(version, "server", "user-add", "localhost")
	if os.Geteuid() != 0 {
		r.Add(report.Result{Control: "privileges", Status: report.Fail, Severity: "critical", Message: "создание пользователя должно выполняться от root"})
		return r
	}
	for _, command := range []string{"useradd", "usermod", "sshd", "ssh-keygen"} {
		if _, err := findCommand(command); err != nil {
			r.Add(report.Result{Control: "preflight", Status: report.Fail, Severity: "critical", Message: err.Error()})
			return r
		}
	}
	if request.GrantSudo {
		if _, err := findCommand("passwd"); err != nil {
			r.Add(report.Result{Control: "preflight", Status: report.Fail, Severity: "critical", Message: err.Error()})
			return r
		}
	}
	account, lookupErr := user.Lookup(request.Username)
	created := false
	if lookupErr != nil {
		var unknown user.UnknownUserError
		if !errors.As(lookupErr, &unknown) {
			r.Add(failResult("account", "не удалось проверить существование пользователя", lookupErr))
			return r
		}
		result := runCommand(ctx, "", "useradd", "--create-home", "--shell", "/bin/bash", "--", request.Username)
		if result.Err != nil {
			r.Add(commandFailure("account", "не удалось создать пользователя", result))
			return r
		}
		created = true
		var err error
		account, err = user.Lookup(request.Username)
		if err != nil {
			r.Add(failResult("account", "пользователь создан, но системная база не вернула его данные", err))
			return r
		}
	}
	uid, gid, err := validateLoginAccount(account)
	if err != nil {
		r.Add(failResult("account", "существующая учётная запись небезопасна для автоматической настройки", err))
		return r
	}
	status := report.Pass
	message := "существующая учётная запись проверена"
	if created {
		status = report.Changed
		message = "создана key-only учётная запись"
	}
	r.Add(report.Result{Control: "account", Status: status, Severity: "high", Message: message, Changed: created, Details: map[string]string{"username": request.Username, "uid": strconv.Itoa(uid), "home": account.HomeDir}})

	keyPath, keyAdded, err := installAuthorizedKey(account, uid, gid, request.PublicKey)
	if err != nil {
		r.Add(failResult("authorized-key", "не удалось безопасно установить публичный ключ; учётная запись и существующие файлы сохранены", err))
		return r
	}
	_, fingerprint, _ := sshkey.NormalizePublicKey(request.PublicKey)
	keyStatus := report.Pass
	keyMessage := "публичный ключ уже установлен"
	if keyAdded {
		keyStatus = report.Changed
		keyMessage = "публичный ключ добавлен без замены существующих ключей"
	}
	r.Add(report.Result{Control: "authorized-key", Status: keyStatus, Severity: "critical", Message: keyMessage, Changed: keyAdded, Details: map[string]string{"path": keyPath, "fingerprint": fingerprint}})

	if request.GrantSudo {
		sudoGroup, err := user.LookupGroup("sudo")
		if err != nil {
			r.Add(failResult("sudo-role", "группа sudo не найдена; ключевой вход уже настроен", err))
			return r
		}
		alreadySudo := accountHasGroup(account, sudoGroup.Gid)
		if !alreadySudo {
			result := runCommand(ctx, "", "usermod", "-aG", "sudo", "--", request.Username)
			if result.Err != nil {
				r.Add(commandFailure("sudo-role", "не удалось добавить пользователя в группу sudo; ключевой вход уже настроен", result))
				return r
			}
		}
		passwordState := runCommand(ctx, "", "passwd", "-S", request.Username)
		sudoStatus := report.Pass
		sudoMessage := "пользователь уже состоит в sudo; проверьте наличие отдельного пароля"
		if !alreadySudo {
			sudoStatus = report.Changed
			sudoMessage = "пользователь добавлен в sudo; задайте ему отдельный пароль через интерактивный passwd"
		}
		r.Add(report.Result{Control: "sudo-role", Status: sudoStatus, Severity: "critical", Message: sudoMessage, Changed: !alreadySudo, Details: map[string]string{"password_state": limitText(passwordState.Stdout, 200)}})
	} else {
		r.Add(report.Result{Control: "sudo-role", Status: report.Pass, Severity: "high", Message: "пользователь не получил административных прав"})
	}

	if err := verifyUserSSH(ctx, request.Username, keyPath); err != nil {
		r.Add(failResult("ssh-login", "sshd не подтвердил key-only вход для пользователя", err))
		return r
	}
	r.Add(report.Result{Control: "ssh-login", Status: report.Pass, Severity: "critical", Message: "sshd принимает публичные ключи для нового пользователя", Details: map[string]string{"username": request.Username}})
	r.Warnings = append(r.Warnings, "закрытый ключ должен оставаться только на клиентском ПК; bastionctl получил и сохранил только публичный ключ")
	return r
}

func accountHasGroup(account *user.User, groupID string) bool {
	groups, err := account.GroupIds()
	if err != nil {
		return false
	}
	for _, value := range groups {
		if value == groupID {
			return true
		}
	}
	return false
}

func validateLoginAccount(account *user.User) (int, int, error) {
	uid, err := strconv.Atoi(account.Uid)
	if err != nil || uid < 1000 {
		return 0, 0, errors.New("UID должен быть не меньше 1000")
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil || gid < 1 {
		return 0, 0, errors.New("основная группа пользователя некорректна")
	}
	if !filepath.IsAbs(account.HomeDir) || account.HomeDir == "/" {
		return 0, 0, errors.New("домашний каталог должен быть абсолютным и не равняться /")
	}
	shell, err := accountLoginShell(account.Username)
	if err != nil {
		return 0, 0, err
	}
	if strings.HasSuffix(shell, "nologin") || strings.HasSuffix(shell, "false") {
		return 0, 0, errors.New("у пользователя запрещена интерактивная оболочка")
	}
	if err := rejectSymlinkParents(account.HomeDir); err != nil {
		return 0, 0, err
	}
	info, err := os.Lstat(account.HomeDir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return 0, 0, errors.New("домашний каталог недоступен или является symlink")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != uid || info.Mode().Perm()&0o022 != 0 {
		return 0, 0, errors.New("домашний каталог имеет небезопасного владельца или доступ на запись для группы/остальных")
	}
	return uid, gid, nil
}

func accountLoginShell(username string) (string, error) {
	file, err := os.Open("/etc/passwd")
	if err != nil {
		return "", err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) >= 7 && fields[0] == username {
			return fields[6], nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", errors.New("пользователь отсутствует в /etc/passwd")
}

func installAuthorizedKey(account *user.User, uid, gid int, publicKey string) (string, bool, error) {
	sshDirectory := filepath.Join(account.HomeDir, ".ssh")
	info, err := os.Lstat(sshDirectory)
	if os.IsNotExist(err) {
		if err := os.Mkdir(sshDirectory, 0o700); err != nil {
			return "", false, err
		}
		if err := os.Chown(sshDirectory, uid, gid); err != nil {
			return "", false, err
		}
	} else if err != nil {
		return "", false, err
	} else {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return "", false, errors.New(".ssh должен быть обычным каталогом без symlink")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || int(stat.Uid) != uid {
			return "", false, errors.New(".ssh принадлежит другому пользователю")
		}
	}
	directoryFD, err := syscall.Open(sshDirectory, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", false, err
	}
	defer syscall.Close(directoryFD)
	var directoryStat syscall.Stat_t
	if err := syscall.Fstat(directoryFD, &directoryStat); err != nil || directoryStat.Mode&syscall.S_IFMT != syscall.S_IFDIR || int(directoryStat.Uid) != uid {
		return "", false, errors.New(".ssh изменился во время проверки или принадлежит другому пользователю")
	}
	if err := syscall.Fchmod(directoryFD, 0o700); err != nil {
		return "", false, err
	}
	keyPath := filepath.Join(sshDirectory, "authorized_keys")
	fd, err := syscall.Openat(directoryFD, "authorized_keys", syscall.O_CREAT|syscall.O_RDWR|syscall.O_APPEND|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return "", false, err
	}
	file := os.NewFile(uintptr(fd), keyPath)
	if file == nil {
		_ = syscall.Close(fd)
		return "", false, errors.New("не удалось открыть authorized_keys")
	}
	defer file.Close()
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		return "", false, err
	}
	defer syscall.Flock(fd, syscall.LOCK_UN)
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		return "", false, err
	}
	if stat.Mode&syscall.S_IFMT != syscall.S_IFREG || stat.Size > 1<<20 {
		return "", false, errors.New("authorized_keys должен быть обычным файлом размером не более 1 MiB")
	}
	if int(stat.Uid) != uid && stat.Uid != 0 {
		return "", false, errors.New("authorized_keys принадлежит другому пользователю")
	}
	if err := syscall.Fchown(fd, uid, gid); err != nil {
		return "", false, err
	}
	if err := syscall.Fchmod(fd, 0o600); err != nil {
		return "", false, err
	}
	content, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil || len(content) > 1<<20 {
		return "", false, errors.New("не удалось безопасно прочитать authorized_keys")
	}
	for _, line := range strings.Split(string(content), "\n") {
		if authorizedLineHasKey(line, publicKey) {
			return keyPath, false, nil
		}
	}
	prefix := ""
	if len(content) > 0 && content[len(content)-1] != '\n' {
		prefix = "\n"
	}
	if _, err := file.WriteString(prefix + publicKey + "\n"); err != nil {
		return "", false, err
	}
	if err := file.Sync(); err != nil {
		return "", false, err
	}
	return keyPath, true, nil
}

func authorizedLineHasKey(line, publicKey string) bool {
	wanted := strings.Fields(publicKey)
	if len(wanted) < 2 {
		return false
	}
	fields := strings.Fields(strings.TrimSpace(line))
	for index := 0; index+1 < len(fields); index++ {
		if fields[index] == wanted[0] && fields[index+1] == wanted[1] {
			return true
		}
	}
	return false
}

func verifyUserSSH(ctx context.Context, username, keyPath string) error {
	keyCheck := runCommand(ctx, "", "ssh-keygen", "-l", "-f", keyPath)
	if keyCheck.Err != nil {
		return fmt.Errorf("ssh-keygen: %s", firstError(keyCheck))
	}
	result := runCommand(ctx, "", "sshd", "-T", "-C", "user="+username+",host=localhost,addr=127.0.0.1")
	if result.Err != nil {
		return fmt.Errorf("sshd -T: %s", firstError(result))
	}
	values := map[string]string{}
	for _, line := range strings.Split(result.Stdout, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 1 {
			values[fields[0]] = strings.Join(fields[1:], " ")
		}
	}
	if values["pubkeyauthentication"] != "yes" || values["authorizedkeysfile"] == "none" {
		return errors.New("pubkeyauthentication отключён или authorizedkeysfile=none")
	}
	return nil
}
