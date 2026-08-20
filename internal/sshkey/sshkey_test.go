package sshkey

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
)

func TestNormalizePublicKey(t *testing.T) {
	value := testPublicKey() + " workstation key"
	normalized, fingerprint, err := NormalizePublicKey(value)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(normalized, "workstation key") || !strings.HasPrefix(fingerprint, "SHA256:") {
		t.Fatalf("normalized=%q fingerprint=%q", normalized, fingerprint)
	}
}

func TestNormalizePublicKeyRejectsUnsafeInput(t *testing.T) {
	for _, value := range []string{"", "ssh-rsa AAAA", testPublicKey() + "\nsecond", "ssh-ed25519 !!!!"} {
		if _, _, err := NormalizePublicKey(value); err == nil {
			t.Fatalf("input should be rejected: %q", value)
		}
	}
}

func TestValidateUsername(t *testing.T) {
	for _, value := range []string{"alice", "deploy_2", "ops-user"} {
		if err := ValidateUsername(value); err != nil {
			t.Errorf("%q: %v", value, err)
		}
	}
	for _, value := range []string{"root", "-bad", "Bad", "a.b", ""} {
		if err := ValidateUsername(value); err == nil {
			t.Errorf("%q should be rejected", value)
		}
	}
}

func testPublicKey() string {
	var blob bytes.Buffer
	write := func(value []byte) {
		_ = binary.Write(&blob, binary.BigEndian, uint32(len(value)))
		_, _ = blob.Write(value)
	}
	write([]byte("ssh-ed25519"))
	write(bytes.Repeat([]byte{0x42}, 32))
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob.Bytes())
}
