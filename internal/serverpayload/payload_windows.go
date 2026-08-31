//go:build windows

package serverpayload

import (
	_ "embed"
	"fmt"
)

// These files are generated from the same source and version immediately
// before the Windows executable is linked.

//go:embed bin/bastionctl-server-ubuntu-amd64
var ubuntuAMD64 []byte

//go:embed bin/bastionctl-server-ubuntu-arm64
var ubuntuARM64 []byte

func ForArchitecture(architecture string) (Payload, error) {
	switch architecture {
	case "amd64":
		return validate("bastionctl-server-ubuntu-amd64", architecture, ubuntuAMD64)
	case "arm64":
		return validate("bastionctl-server-ubuntu-arm64", architecture, ubuntuARM64)
	default:
		return Payload{}, fmt.Errorf("для архитектуры %q нет встроенного Ubuntu-компонента", architecture)
	}
}
