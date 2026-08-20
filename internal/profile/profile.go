package profile

import (
	"errors"
	"sort"

	"bastionctl/internal/config"
)

type Profile struct {
	Name        string `json:"name"`
	Title       string `json:"title"`
	Description string `json:"description"`
	TCPPorts    []int  `json:"tcp_ports"`
	UDPPorts    []int  `json:"udp_ports"`
}

var builtins = map[string]Profile{
	"minimal": {
		Name: "minimal", Title: "Минимальный сервер",
		Description: "Только SSH и системная защита; публичные сервисные порты не открываются.",
	},
	"web": {
		Name: "web", Title: "Веб-сервер",
		Description: "HTTP/HTTPS на 80 и 443, остальная базовая защита без изменений.",
		TCPPorts:    []int{80, 443},
	},
	"docker-host": {
		Name: "docker-host", Title: "Docker host",
		Description: "HTTP/HTTPS и усиленный аудит published ports; Docker firewall требует ручной проверки.",
		TCPPorts:    []int{80, 443},
	},
	"wireguard": {
		Name: "wireguard", Title: "WireGuard",
		Description: "Открывает UDP 51820; IP forwarding автоматически не меняется.",
		UDPPorts:    []int{51820},
	},
	"database": {
		Name: "database", Title: "Сервер базы данных",
		Description: "Порты базы не публикуются; доступ предполагается через VPN или приватную сеть.",
	},
}

func Names() []string {
	names := make([]string, 0, len(builtins))
	for name := range builtins {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func List() []Profile {
	names := Names()
	result := make([]Profile, 0, len(names))
	for _, name := range names {
		item := builtins[name]
		item.TCPPorts = append([]int(nil), item.TCPPorts...)
		item.UDPPorts = append([]int(nil), item.UDPPorts...)
		result = append(result, item)
	}
	return result
}

func Get(name string) (Profile, bool) {
	item, ok := builtins[name]
	if !ok {
		return Profile{}, false
	}
	item.TCPPorts = append([]int(nil), item.TCPPorts...)
	item.UDPPorts = append([]int(nil), item.UDPPorts...)
	return item, true
}

func Apply(name string, cfg config.Config) (config.Config, error) {
	item, ok := Get(name)
	if !ok {
		return config.Config{}, errors.New("неизвестный профиль " + name)
	}
	cfg.Server.Profile = item.Name
	cfg.Server.AllowedTCPPorts = append([]int(nil), item.TCPPorts...)
	cfg.Server.AllowedUDPPorts = append([]int(nil), item.UDPPorts...)
	if err := cfg.Validate(); err != nil {
		return config.Config{}, err
	}
	return cfg, nil
}
