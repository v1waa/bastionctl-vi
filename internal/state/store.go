package state

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"bastionctl/internal/inventory"
	"bastionctl/internal/report"
)

const (
	registrySchema       = "bastionctl.registry.v2"
	legacyRegistrySchema = "bastionctl.registry.v1"
)

type ManagedServer struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	Target           string    `json:"target"`
	Port             int       `json:"port"`
	Identity         string    `json:"identity,omitempty"`
	Profile          string    `json:"profile"`
	ConfigPath       string    `json:"config_path"`
	ServerBinary     string    `json:"server_binary,omitempty"`
	BootstrapTarget  string    `json:"bootstrap_target,omitempty"`
	BootstrapPending bool      `json:"bootstrap_pending,omitempty"`
	InteractiveSudo  bool      `json:"interactive_sudo,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
	LastSeenAt       time.Time `json:"last_seen_at,omitempty"`
	LastAction       string    `json:"last_action,omitempty"`
	LastStatus       string    `json:"last_status,omitempty"`
}

type Registry struct {
	Schema  string          `json:"schema"`
	Servers []ManagedServer `json:"servers"`
}

type HistoryEntry struct {
	Path      string    `json:"path"`
	Action    string    `json:"action"`
	Timestamp time.Time `json:"timestamp"`
	HasFails  bool      `json:"has_failures"`
}

type SignedSnapshot struct {
	Schema    string             `json:"schema"`
	Snapshot  inventory.Snapshot `json:"snapshot"`
	PublicKey string             `json:"public_key"`
	Signature string             `json:"signature"`
}

type Store struct {
	root string
	mu   sync.Mutex
}

var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

func DefaultRoot() (string, error) {
	directory, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(directory, "bastionctl"), nil
}

func Open(root string) (*Store, error) {
	if root == "" {
		var err error
		root, err = DefaultRoot()
		if err != nil {
			return nil, fmt.Errorf("определить каталог приложения: %w", err)
		}
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if info, statErr := os.Lstat(root); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("каталог состояния не может быть символической ссылкой")
	} else if statErr != nil && !os.IsNotExist(statErr) {
		return nil, statErr
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("создать каталог состояния: %w", err)
	}
	_ = os.Chmod(root, 0o700)
	return &Store{root: root}, nil
}

func (s *Store) Root() string { return s.root }

func ValidateID(id string) error {
	if !idPattern.MatchString(id) {
		return errors.New("ID должен содержать 1–32 символа: a-z, 0-9, _ или -")
	}
	return nil
}

func (s *Store) LoadRegistry() (Registry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadRegistryUnlocked()
}

func (s *Store) loadRegistryUnlocked() (Registry, error) {
	path := filepath.Join(s.root, "registry.json")
	data, err := readRegular(path)
	if os.IsNotExist(err) {
		return Registry{Schema: registrySchema, Servers: []ManagedServer{}}, nil
	}
	if err != nil {
		return Registry{}, err
	}
	var registry Registry
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&registry); err != nil {
		return Registry{}, fmt.Errorf("прочитать реестр: %w", err)
	}
	if registry.Schema != registrySchema && registry.Schema != legacyRegistrySchema {
		return Registry{}, fmt.Errorf("неподдерживаемая схема реестра %q", registry.Schema)
	}
	registry.Schema = registrySchema
	for _, item := range registry.Servers {
		if err := s.validateServer(item); err != nil {
			return Registry{}, fmt.Errorf("сервер %q: %w", item.ID, err)
		}
	}
	return registry, nil
}

func (s *Store) saveRegistryUnlocked(registry Registry) error {
	registry.Schema = registrySchema
	sort.Slice(registry.Servers, func(i, j int) bool { return registry.Servers[i].ID < registry.Servers[j].ID })
	data, err := json.MarshalIndent(registry, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(s.root, "registry.json"), append(data, '\n'), 0o600)
}

func (s *Store) AddServer(item ManagedServer) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	registry, err := s.loadRegistryUnlocked()
	if err != nil {
		return err
	}
	for _, existing := range registry.Servers {
		if existing.ID == item.ID {
			return fmt.Errorf("сервер с ID %q уже существует", item.ID)
		}
	}
	now := time.Now().UTC()
	item.CreatedAt = now
	item.UpdatedAt = now
	if err := s.validateServer(item); err != nil {
		return err
	}
	registry.Servers = append(registry.Servers, item)
	return s.saveRegistryUnlocked(registry)
}

func (s *Store) UpdateServer(item ManagedServer) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	registry, err := s.loadRegistryUnlocked()
	if err != nil {
		return err
	}
	found := false
	for index := range registry.Servers {
		if registry.Servers[index].ID == item.ID {
			item.CreatedAt = registry.Servers[index].CreatedAt
			item.UpdatedAt = time.Now().UTC()
			registry.Servers[index] = item
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("сервер %q не найден", item.ID)
	}
	if err := s.validateServer(item); err != nil {
		return err
	}
	return s.saveRegistryUnlocked(registry)
}

func (s *Store) RemoveServer(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	registry, err := s.loadRegistryUnlocked()
	if err != nil {
		return err
	}
	filtered := make([]ManagedServer, 0, len(registry.Servers))
	for _, item := range registry.Servers {
		if item.ID != id {
			filtered = append(filtered, item)
		}
	}
	if len(filtered) == len(registry.Servers) {
		return fmt.Errorf("сервер %q не найден", id)
	}
	registry.Servers = filtered
	return s.saveRegistryUnlocked(registry)
}

func (s *Store) Server(id string) (ManagedServer, error) {
	registry, err := s.LoadRegistry()
	if err != nil {
		return ManagedServer{}, err
	}
	for _, item := range registry.Servers {
		if item.ID == id {
			return item, nil
		}
	}
	return ManagedServer{}, fmt.Errorf("сервер %q не найден", id)
}

func (s *Store) ServerDirectory(id string) (string, error) {
	if err := ValidateID(id); err != nil {
		return "", err
	}
	serversRoot := filepath.Join(s.root, "servers")
	if info, err := os.Lstat(serversRoot); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return "", errors.New("каталог servers должен быть обычным каталогом без symlink")
		}
	} else if !os.IsNotExist(err) {
		return "", err
	}
	if err := os.MkdirAll(serversRoot, 0o700); err != nil {
		return "", err
	}
	_ = os.Chmod(serversRoot, 0o700)
	path := filepath.Join(serversRoot, id)
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return "", errors.New("каталог сервера должен быть обычным каталогом без symlink")
		}
	} else if !os.IsNotExist(err) {
		return "", err
	}
	if err := os.Mkdir(path, 0o700); err != nil && !os.IsExist(err) {
		return "", err
	}
	_ = os.Chmod(path, 0o700)
	return path, nil
}

func (s *Store) ServerIdentityPath(id string) (string, error) {
	directory, err := s.ServerDirectory(id)
	if err != nil {
		return "", err
	}
	return filepath.Join(directory, "id_ed25519"), nil
}

func (s *Store) SaveServerConfig(id string, data []byte) (string, error) {
	directory, err := s.ServerDirectory(id)
	if err != nil {
		return "", err
	}
	path := filepath.Join(directory, "config.toml")
	if err := atomicWrite(path, data, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func (s *Store) SaveReport(id string, value *report.Report) (string, error) {
	if err := ValidateID(id); err != nil {
		return "", err
	}
	value.Finish()
	directory := filepath.Join(s.root, "history", id)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", err
	}
	name := value.FinishedAt.UTC().Format("20060102T150405.000000000Z") + "-" + safeComponent(value.Action) + ".json"
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return "", err
	}
	path := filepath.Join(directory, name)
	if err := atomicWrite(path, append(data, '\n'), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func (s *Store) History(id string, limit int) ([]HistoryEntry, error) {
	if err := ValidateID(id); err != nil {
		return nil, err
	}
	directory := filepath.Join(s.root, "history", id)
	entries, err := os.ReadDir(directory)
	if os.IsNotExist(err) {
		return []HistoryEntry{}, nil
	}
	if err != nil {
		return nil, err
	}
	result := make([]HistoryEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		value, readErr := loadReport(path)
		if readErr != nil {
			return nil, readErr
		}
		result = append(result, HistoryEntry{Path: path, Action: value.Action, Timestamp: value.FinishedAt, HasFails: value.HasFailures()})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Timestamp.After(result[j].Timestamp) })
	if limit > 0 && len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}

func (s *Store) LatestReport(id, action string) (*report.Report, error) {
	entries, err := s.History(id, 0)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if action == "" || entry.Action == action {
			value, loadErr := loadReport(entry.Path)
			if loadErr != nil {
				return nil, loadErr
			}
			return &value, nil
		}
	}
	return nil, os.ErrNotExist
}

func (s *Store) SaveSnapshot(id string, snapshot inventory.Snapshot, setBaseline bool) error {
	if err := ValidateID(id); err != nil {
		return err
	}
	if err := snapshot.Validate(); err != nil {
		return err
	}
	record, err := s.signSnapshot(snapshot)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	directory := filepath.Join(s.root, "snapshots", id)
	historyDirectory := filepath.Join(directory, "history")
	if err := os.MkdirAll(historyDirectory, 0o700); err != nil {
		return err
	}
	data = append(data, '\n')
	if err := atomicWrite(filepath.Join(directory, "latest.json"), data, 0o600); err != nil {
		return err
	}
	historyName := snapshot.CapturedAt.UTC().Format("20060102T150405.000000000Z") + ".json"
	if err := atomicWrite(filepath.Join(historyDirectory, historyName), data, 0o600); err != nil {
		return err
	}
	if setBaseline {
		if err := atomicWrite(filepath.Join(directory, "baseline.json"), data, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) LoadSnapshot(id, kind string) (inventory.Snapshot, error) {
	if err := ValidateID(id); err != nil {
		return inventory.Snapshot{}, err
	}
	if kind != "baseline" && kind != "latest" {
		return inventory.Snapshot{}, errors.New("kind должен быть baseline или latest")
	}
	data, err := readRegular(filepath.Join(s.root, "snapshots", id, kind+".json"))
	if err != nil {
		return inventory.Snapshot{}, err
	}
	var record SignedSnapshot
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return inventory.Snapshot{}, err
	}
	if record.Schema != "bastionctl.signed-snapshot.v1" {
		return inventory.Snapshot{}, errors.New("неподдерживаемая signed snapshot schema")
	}
	payload, err := json.Marshal(record.Snapshot)
	if err != nil {
		return inventory.Snapshot{}, err
	}
	publicKey, err := base64.StdEncoding.DecodeString(record.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return inventory.Snapshot{}, errors.New("некорректный публичный ключ snapshot")
	}
	trustedKey, err := s.integrityPublicKey()
	if err != nil {
		return inventory.Snapshot{}, err
	}
	if !bytes.Equal(publicKey, trustedKey) {
		return inventory.Snapshot{}, errors.New("snapshot подписан неизвестным локальным ключом")
	}
	signature, err := base64.StdEncoding.DecodeString(record.Signature)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(publicKey), payload, signature) {
		return inventory.Snapshot{}, errors.New("подпись snapshot не прошла проверку")
	}
	if err := record.Snapshot.Validate(); err != nil {
		return inventory.Snapshot{}, err
	}
	return record.Snapshot, nil
}

func (s *Store) signSnapshot(snapshot inventory.Snapshot) (SignedSnapshot, error) {
	privateKey, err := s.integrityKey()
	if err != nil {
		return SignedSnapshot{}, err
	}
	payload, err := json.Marshal(snapshot)
	if err != nil {
		return SignedSnapshot{}, err
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return SignedSnapshot{
		Schema: "bastionctl.signed-snapshot.v1", Snapshot: snapshot,
		PublicKey: base64.StdEncoding.EncodeToString(publicKey),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload)),
	}, nil
}

func (s *Store) integrityKey() (ed25519.PrivateKey, error) {
	path := filepath.Join(s.root, "integrity.key")
	data, err := readRegular(path)
	if err == nil {
		if len(data) != ed25519.PrivateKeySize {
			return nil, errors.New("локальный ключ целостности имеет неверный размер")
		}
		return ed25519.PrivateKey(data), nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := atomicWrite(path, privateKey, 0o600); err != nil {
		return nil, err
	}
	return privateKey, nil
}

func (s *Store) integrityPublicKey() (ed25519.PublicKey, error) {
	data, err := readRegular(filepath.Join(s.root, "integrity.key"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.New("локальный ключ целостности отсутствует")
		}
		return nil, err
	}
	if len(data) != ed25519.PrivateKeySize {
		return nil, errors.New("локальный ключ целостности имеет неверный размер")
	}
	return ed25519.PrivateKey(data).Public().(ed25519.PublicKey), nil
}

func (s *Store) validateServer(item ManagedServer) error {
	if err := ValidateID(item.ID); err != nil {
		return err
	}
	if strings.TrimSpace(item.Name) == "" || len(item.Name) > 100 {
		return errors.New("имя сервера обязательно и не должно превышать 100 символов")
	}
	if item.Target == "" || item.Port < 1 || item.Port > 65535 || item.Profile == "" || item.ConfigPath == "" {
		return errors.New("target, port, profile и config_path обязательны")
	}
	if item.BootstrapPending && (item.BootstrapTarget == "" || item.Identity == "") {
		return errors.New("ожидающий bootstrap требует bootstrap_target и identity")
	}
	expected := filepath.Clean(filepath.Join(s.root, "servers", item.ID, "config.toml"))
	actual, err := filepath.Abs(item.ConfigPath)
	if err != nil || filepath.Clean(actual) != expected {
		return errors.New("config_path должен указывать на управляемый файл внутри каталога состояния")
	}
	return nil
}

func loadReport(path string) (report.Report, error) {
	data, err := readRegular(path)
	if err != nil {
		return report.Report{}, err
	}
	var value report.Report
	if err := json.Unmarshal(data, &value); err != nil {
		return report.Report{}, err
	}
	if value.Schema != report.Schema {
		return report.Report{}, errors.New("неподдерживаемая схема отчёта")
	}
	return value, nil
}

func readRegular(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("ожидался обычный файл без symlink: " + path)
	}
	return os.ReadFile(path)
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return errors.New("отказ записи через symlink: " + path)
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".bastionctl-*")
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
	if err := temporary.Chmod(mode); err != nil {
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
	success = true
	return nil
}

func safeComponent(value string) string {
	var output strings.Builder
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-' || char == '_' {
			output.WriteRune(char)
		}
	}
	if output.Len() == 0 {
		return "report"
	}
	return output.String()
}
