package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"bastionctl/internal/config"
	"bastionctl/internal/inventory"
)

func CaptureSnapshot(ctx context.Context, cfg config.AdminConfig, version string, options Options) (inventory.Snapshot, error) {
	parts := []string{"sudo", "-n", cfg.RemoteExecutable, "server", "snapshot", "--config", cfg.RemoteConfig, "--json"}
	stdout, stderr, err := runRawSSH(ctx, cfg, options, remoteCommand(parts), 10*time.Minute)
	if err != nil {
		message := strings.TrimSpace(string(stderr))
		if message == "" {
			message = err.Error()
		}
		return inventory.Snapshot{}, fmt.Errorf("удалённый snapshot: %s", limit(message, 4000))
	}
	var snapshot inventory.Snapshot
	decoder := json.NewDecoder(bytes.NewReader(stdout))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&snapshot); err != nil {
		return inventory.Snapshot{}, fmt.Errorf("декодировать snapshot: %w", err)
	}
	if err := snapshot.Validate(); err != nil {
		return inventory.Snapshot{}, err
	}
	if snapshot.ToolVersion != version {
		snapshot.Warnings = append(snapshot.Warnings, fmt.Sprintf("локальная версия %s, серверная версия %s", version, snapshot.ToolVersion))
	}
	return snapshot, nil
}
