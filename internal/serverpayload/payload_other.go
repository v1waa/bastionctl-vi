//go:build !windows

package serverpayload

import "fmt"

func ForArchitecture(architecture string) (Payload, error) {
	return Payload{}, fmt.Errorf("встроенные Ubuntu-компоненты доступны только в Windows-приложении, запрошена архитектура %q", architecture)
}
