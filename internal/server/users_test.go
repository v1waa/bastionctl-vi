package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"

	"bastionctl/internal/config"
)

func TestNewUserRequestValidatesBoundary(t *testing.T) {
	request, err := NewUserRequest("alice", userTestPublicKey(), false)
	if err != nil {
		t.Fatal(err)
	}
	if request.Schema != userRequestSchema || request.Username != "alice" || request.GrantSudo {
		t.Fatalf("unexpected request: %+v", request)
	}
	if _, err := NewUserRequest("root", userTestPublicKey(), false); err == nil {
		t.Fatal("root must be rejected")
	}
}

func TestCreateUserRejectsUnknownAndTrailingJSONBeforePlatform(t *testing.T) {
	for _, payload := range []string{
		`{"schema":"wrong","username":"alice","public_key":"x","grant_sudo":false}`,
		`{"schema":"bastionctl.user-add.v1","username":"alice","public_key":"x","grant_sudo":false,"extra":1}`,
		`{} {}`,
	} {
		r := CreateUser(context.Background(), config.Defaults(), "test", strings.NewReader(payload), true)
		if !r.HasFailures() || len(r.Results) == 0 || r.Results[0].Control != "request" {
			t.Fatalf("payload=%q report=%+v", payload, r)
		}
	}
}

func userTestPublicKey() string {
	var blob bytes.Buffer
	write := func(value []byte) {
		_ = binary.Write(&blob, binary.BigEndian, uint32(len(value)))
		_, _ = blob.Write(value)
	}
	write([]byte("ssh-ed25519"))
	write(bytes.Repeat([]byte{0x24}, 32))
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob.Bytes()) + " server-test"
}
