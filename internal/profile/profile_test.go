package profile

import (
	"reflect"
	"testing"

	"bastionctl/internal/config"
)

func TestApplyProfiles(t *testing.T) {
	cfg, err := Apply("wireguard", config.Defaults())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Profile != "wireguard" || !reflect.DeepEqual(cfg.Server.AllowedUDPPorts, []int{51820}) {
		t.Fatalf("unexpected profile: %+v", cfg.Server)
	}
	if _, err := Apply("unknown", cfg); err == nil {
		t.Fatal("unknown profile accepted")
	}
}

func TestGetReturnsCopies(t *testing.T) {
	first, _ := Get("web")
	first.TCPPorts[0] = 1234
	second, _ := Get("web")
	if second.TCPPorts[0] != 80 {
		t.Fatal("profile storage was mutated")
	}
}
