//go:build !linux

package server

import (
	"context"
	"errors"

	"bastionctl/internal/config"
	"bastionctl/internal/inventory"
)

func capturePlatform(_ context.Context, _ config.Config, _, _ string) (inventory.Snapshot, error) {
	return inventory.Snapshot{}, errors.New("server snapshot поддерживается только на Linux")
}
