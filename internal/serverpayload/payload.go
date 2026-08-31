package serverpayload

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"bastionctl/internal/admin"
)

const maximumPayloadSize = 100 << 20

type Payload struct {
	Name         string `json:"name"`
	Architecture string `json:"architecture"`
	SHA256       string `json:"sha256"`
	Data         []byte `json:"-"`
}

func validate(name, architecture string, data []byte) (Payload, error) {
	if name == "" || len(data) < 20 || len(data) > maximumPayloadSize {
		return Payload{}, errors.New("встроенный Ubuntu-компонент отсутствует или имеет недопустимый размер")
	}
	detected, err := admin.ELFArchitectureData(data)
	if err != nil {
		return Payload{}, fmt.Errorf("проверить встроенный Ubuntu-компонент: %w", err)
	}
	if detected != architecture {
		return Payload{}, fmt.Errorf("встроенный компонент %s не соответствует заявленной архитектуре %s", detected, architecture)
	}
	digest := sha256.Sum256(data)
	return Payload{Name: name, Architecture: architecture, SHA256: hex.EncodeToString(digest[:]), Data: data}, nil
}
