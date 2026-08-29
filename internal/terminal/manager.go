package terminal

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

type Event struct {
	SessionID string `json:"session_id"`
	ServerID  string `json:"server_id"`
	Kind      string `json:"kind"`
	Data      string `json:"data,omitempty"`
	Encoding  string `json:"encoding,omitempty"`
	Error     string `json:"error,omitempty"`
}

type Emitter func(Event)

type Handle struct {
	ID   string
	Done <-chan error
}

type managedSession struct {
	id       string
	serverID string
	client   *ssh.Client
	session  *ssh.Session
	stdin    io.WriteCloser
	done     chan error
	close    sync.Once
}

type Manager struct {
	mu       sync.Mutex
	sessions map[string]*managedSession
	emit     Emitter
}

func NewManager(emit Emitter) *Manager {
	if emit == nil {
		emit = func(Event) {}
	}
	return &Manager{sessions: make(map[string]*managedSession), emit: emit}
}

func (m *Manager) StartShell(ctx context.Context, connection Connection, credentials Credentials, columns, rows int) (Handle, error) {
	return m.start(ctx, connection, credentials, columns, rows, "")
}

func (m *Manager) StartCommand(ctx context.Context, connection Connection, credentials Credentials, columns, rows int, command string) (Handle, error) {
	if strings.TrimSpace(command) == "" || len(command) > 64*1024 || strings.ContainsRune(command, '\x00') {
		return Handle{}, errors.New("удалённая команда отсутствует или недопустима")
	}
	return m.start(ctx, connection, credentials, columns, rows, command)
}

func (m *Manager) start(ctx context.Context, connection Connection, credentials Credentials, columns, rows int, command string) (Handle, error) {
	columns, rows = safeTerminalSize(columns, rows)
	client, err := Dial(ctx, connection, credentials)
	if err != nil {
		return Handle{}, err
	}
	session, err := client.NewSession()
	if err != nil {
		client.Close()
		return Handle{}, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = session.Close()
			_ = client.Close()
		}
	}()
	terminalModes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 115200,
		ssh.TTY_OP_OSPEED: 115200,
	}
	if err := session.RequestPty("xterm-256color", rows, columns, terminalModes); err != nil {
		return Handle{}, fmt.Errorf("запросить remote PTY: %w", err)
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		return Handle{}, err
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		return Handle{}, err
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		return Handle{}, err
	}
	if command == "" {
		err = session.Shell()
	} else {
		err = session.Start(command)
	}
	if err != nil {
		return Handle{}, fmt.Errorf("запустить удалённую сессию: %w", err)
	}
	id, err := randomSessionID()
	if err != nil {
		return Handle{}, err
	}
	done := make(chan error, 1)
	current := &managedSession{id: id, serverID: connection.ServerID, client: client, session: session, stdin: stdin, done: done}
	m.mu.Lock()
	m.sessions[id] = current
	m.mu.Unlock()
	cleanup = false
	m.emit(Event{SessionID: id, ServerID: connection.ServerID, Kind: "connected"})
	go m.run(ctx, current, stdout, stderr)
	return Handle{ID: id, Done: done}, nil
}

func (m *Manager) run(ctx context.Context, current *managedSession, stdout, stderr io.Reader) {
	readDone := make(chan struct{}, 2)
	for _, reader := range []io.Reader{stdout, stderr} {
		go func(source io.Reader) {
			m.copyOutput(current, source)
			readDone <- struct{}{}
		}(reader)
	}
	waitDone := make(chan error, 1)
	go func() { waitDone <- current.session.Wait() }()
	var err error
	select {
	case err = <-waitDone:
	case <-ctx.Done():
		err = ctx.Err()
		_ = current.session.Close()
		_ = current.client.Close()
		<-waitDone
	}
	<-readDone
	<-readDone
	m.remove(current.id)
	current.done <- err
	close(current.done)
	event := Event{SessionID: current.id, ServerID: current.serverID, Kind: "closed"}
	if err != nil && !errors.Is(err, io.EOF) {
		event.Error = err.Error()
	}
	m.emit(event)
}

func (m *Manager) copyOutput(current *managedSession, reader io.Reader) {
	buffer := make([]byte, 32*1024)
	for {
		count, err := reader.Read(buffer)
		if count > 0 {
			data := base64.StdEncoding.EncodeToString(buffer[:count])
			m.emit(Event{SessionID: current.id, ServerID: current.serverID, Kind: "data", Data: data, Encoding: "base64"})
		}
		if err != nil {
			return
		}
	}
}

func (m *Manager) Write(sessionID, data string) error {
	if len(data) == 0 || len(data) > 64*1024 {
		return errors.New("terminal input пуст или слишком велик")
	}
	current, err := m.get(sessionID)
	if err != nil {
		return err
	}
	_, err = io.WriteString(current.stdin, data)
	return err
}

func (m *Manager) Resize(sessionID string, columns, rows int) error {
	columns, rows = safeTerminalSize(columns, rows)
	current, err := m.get(sessionID)
	if err != nil {
		return err
	}
	return current.session.WindowChange(rows, columns)
}

func (m *Manager) Stop(sessionID string) error {
	current, err := m.get(sessionID)
	if err != nil {
		return err
	}
	var closeErr error
	current.close.Do(func() {
		closeErr = errors.Join(current.session.Close(), current.client.Close())
	})
	return closeErr
}

func (m *Manager) Close() error {
	m.mu.Lock()
	values := make([]*managedSession, 0, len(m.sessions))
	for _, current := range m.sessions {
		values = append(values, current)
	}
	m.mu.Unlock()
	var result error
	for _, current := range values {
		result = errors.Join(result, m.Stop(current.id))
	}
	return result
}

func (m *Manager) get(id string) (*managedSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	current, ok := m.sessions[id]
	if !ok {
		return nil, errors.New("terminal session не найдена")
	}
	return current, nil
}

func (m *Manager) remove(id string) {
	m.mu.Lock()
	delete(m.sessions, id)
	m.mu.Unlock()
}

func safeTerminalSize(columns, rows int) (int, int) {
	if columns < 20 {
		columns = 80
	}
	if columns > 500 {
		columns = 500
	}
	if rows < 5 {
		rows = 24
	}
	if rows > 300 {
		rows = 300
	}
	return columns, rows
}

func randomSessionID() (string, error) {
	data := make([]byte, 16)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return hex.EncodeToString(data), nil
}
