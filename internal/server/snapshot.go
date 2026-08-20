package server

import (
	"context"

	"bastionctl/internal/config"
	"bastionctl/internal/inventory"
)

func Capture(ctx context.Context, cfg config.Config, version, configPath string) (inventory.Snapshot, error) {
	return capturePlatform(ctx, cfg, version, configPath)
}
