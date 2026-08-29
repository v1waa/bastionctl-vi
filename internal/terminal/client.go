package terminal

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const maximumCommandOutput = 4 << 20

type Connection struct {
	ServerID       string        `json:"server_id"`
	Target         string        `json:"target"`
	Port           int           `json:"port"`
	Identity       string        `json:"identity,omitempty"`
	KnownHosts     string        `json:"-"`
	ConnectTimeout time.Duration `json:"-"`
}

type Credentials struct {
	Password   string `json:"password,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
}

var terminalUserPattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_.-]{0,31}$`)

func Dial(ctx context.Context, connection Connection, credentials Credentials) (*ssh.Client, error) {
	user, host, err := splitTarget(connection.Target)
	if err != nil {
		return nil, err
	}
	if connection.Port < 1 || connection.Port > 65535 {
		return nil, errors.New("SSH-порт должен быть в диапазоне 1..65535")
	}
	callback, err := PinnedHostKeyCallback(connection.KnownHosts)
	if err != nil {
		return nil, err
	}
	auth, err := authenticationMethods(connection.Identity, credentials)
	if err != nil {
		return nil, err
	}
	if len(auth) == 0 {
		return nil, errors.New("для встроенной консоли укажите закрытый ключ или одноразовый пароль")
	}
	timeout := connection.ConnectTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	address := net.JoinHostPort(host, strconv.Itoa(connection.Port))
	config := secureClientConfig(user, auth, callback, timeout)
	network, err := (&net.Dialer{Timeout: timeout, KeepAlive: 15 * time.Second}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("подключиться к SSH: %w", err)
	}
	clientConnection, channels, requests, err := ssh.NewClientConn(network, address, config)
	if err != nil {
		_ = network.Close()
		return nil, fmt.Errorf("SSH handshake/authentication: %w", err)
	}
	return ssh.NewClient(clientConnection, channels, requests), nil
}

type CommandResult struct {
	Stdout string `json:"stdout"`
	Stderr string `json:"stderr"`
}

func RunCommand(ctx context.Context, connection Connection, credentials Credentials, command string, input []byte) (CommandResult, error) {
	if strings.TrimSpace(command) == "" || len(command) > 64*1024 || strings.ContainsRune(command, '\x00') {
		return CommandResult{}, errors.New("удалённая команда отсутствует или недопустима")
	}
	if len(input) > 2<<20 {
		return CommandResult{}, errors.New("ввод удалённой команды слишком велик")
	}
	client, err := Dial(ctx, connection, credentials)
	if err != nil {
		return CommandResult{}, err
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return CommandResult{}, err
	}
	defer session.Close()
	session.Stdin = bytes.NewReader(input)
	stdout := &boundedBuffer{maximum: maximumCommandOutput}
	stderr := &boundedBuffer{maximum: maximumCommandOutput}
	session.Stdout = stdout
	session.Stderr = stderr
	done := make(chan error, 1)
	go func() { done <- session.Run(command) }()
	select {
	case err := <-done:
		result := CommandResult{Stdout: stdout.String(), Stderr: stderr.String()}
		if err != nil {
			return result, fmt.Errorf("удалённая команда: %w", err)
		}
		return result, nil
	case <-ctx.Done():
		_ = session.Close()
		_ = client.Close()
		<-done
		return CommandResult{Stdout: stdout.String(), Stderr: stderr.String()}, ctx.Err()
	}
}

type boundedBuffer struct {
	buffer  bytes.Buffer
	maximum int
	written int
}

func (b *boundedBuffer) Write(value []byte) (int, error) {
	original := len(value)
	b.written += original
	remaining := b.maximum - b.buffer.Len()
	if remaining > 0 {
		if len(value) > remaining {
			value = value[:remaining]
		}
		_, _ = b.buffer.Write(value)
	}
	if b.written > b.maximum {
		return original, errors.New("вывод удалённой команды превысил допустимый размер")
	}
	return original, nil
}

func (b *boundedBuffer) String() string {
	return strings.ToValidUTF8(b.buffer.String(), "�")
}

func secureClientConfig(user string, auth []ssh.AuthMethod, callback ssh.HostKeyCallback, timeout time.Duration) *ssh.ClientConfig {
	algorithms := ssh.SupportedAlgorithms()
	return &ssh.ClientConfig{
		User: user, Auth: auth, HostKeyCallback: callback, Timeout: timeout,
		HostKeyAlgorithms: algorithms.HostKeys,
		Config: ssh.Config{
			KeyExchanges: algorithms.KeyExchanges,
			Ciphers:      algorithms.Ciphers,
			MACs:         algorithms.MACs,
		},
	}
}

func authenticationMethods(identity string, credentials Credentials) ([]ssh.AuthMethod, error) {
	methods := make([]ssh.AuthMethod, 0, 3)
	if strings.TrimSpace(identity) != "" {
		info, err := os.Lstat(identity)
		if err != nil {
			return nil, fmt.Errorf("прочитать закрытый ключ: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 1<<20 {
			return nil, errors.New("закрытый ключ имеет небезопасный тип или размер")
		}
		data, err := os.ReadFile(identity)
		if err != nil {
			return nil, err
		}
		var signer ssh.Signer
		if credentials.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(data, []byte(credentials.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey(data)
		}
		for index := range data {
			data[index] = 0
		}
		if err != nil {
			var passphraseMissing *ssh.PassphraseMissingError
			if errors.As(err, &passphraseMissing) {
				return nil, errors.New("закрытый ключ зашифрован; введите passphrase")
			}
			return nil, fmt.Errorf("разобрать закрытый ключ: %w", err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if credentials.Password != "" {
		password := credentials.Password
		methods = append(methods,
			ssh.Password(password),
			ssh.KeyboardInteractive(func(_ string, _ string, questions []string, echoes []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for index := range questions {
					if index < len(echoes) && echoes[index] {
						return nil, errors.New("сервер запросил непредусмотренный открытый keyboard-interactive ответ")
					}
					answers[index] = password
				}
				return answers, nil
			}),
		)
	}
	return methods, nil
}

func splitTarget(target string) (string, string, error) {
	if strings.ContainsAny(target, "\r\n\x00 /\\") {
		return "", "", errors.New("SSH-цель содержит недопустимые символы")
	}
	separator := strings.LastIndex(target, "@")
	if separator < 1 || separator == len(target)-1 || strings.Contains(target[separator+1:], "@") {
		return "", "", errors.New("SSH-цель должна иметь вид user@host")
	}
	user := target[:separator]
	host := strings.Trim(target[separator+1:], "[]")
	if !terminalUserPattern.MatchString(user) || host == "" || strings.HasPrefix(host, "-") {
		return "", "", errors.New("SSH-цель должна иметь безопасный вид user@host")
	}
	return user, host, nil
}
