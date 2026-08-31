package serverpayload

import (
	"encoding/binary"
	"runtime"
	"testing"
)

func TestValidatePayloadArchitectureAndDigest(t *testing.T) {
	data := make([]byte, 64)
	copy(data, []byte{0x7f, 'E', 'L', 'F'})
	data[4] = 2
	data[5] = 1
	binary.LittleEndian.PutUint16(data[18:20], 62)
	payload, err := validate("ubuntu-amd64", "amd64", data)
	if err != nil {
		t.Fatal(err)
	}
	if payload.Architecture != "amd64" || len(payload.SHA256) != 64 || len(payload.Data) != len(data) {
		t.Fatalf("unexpected payload: %+v", payload)
	}
	if _, err := validate("ubuntu-arm64", "arm64", data); err == nil {
		t.Fatal("architecture mismatch was accepted")
	}
}

func TestWindowsExecutableContainsBothUbuntuPayloads(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("embedded payloads belong to the Windows build")
	}
	for _, architecture := range []string{"amd64", "arm64"} {
		payload, err := ForArchitecture(architecture)
		if err != nil {
			t.Fatalf("%s: %v", architecture, err)
		}
		if len(payload.Data) < 1<<20 || payload.Architecture != architecture || len(payload.SHA256) != 64 {
			t.Fatalf("invalid embedded %s payload: size=%d arch=%s sha=%q", architecture, len(payload.Data), payload.Architecture, payload.SHA256)
		}
	}
}
