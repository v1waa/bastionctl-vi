package inventory

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

const Schema = "bastionctl.snapshot.v1"

type Snapshot struct {
	Schema      string       `json:"schema"`
	ToolVersion string       `json:"tool_version"`
	CapturedAt  time.Time    `json:"captured_at"`
	Host        Host         `json:"host"`
	Packages    []Package    `json:"packages"`
	Services    []Service    `json:"services"`
	Accounts    []Account    `json:"accounts"`
	Listeners   []Listener   `json:"listeners"`
	Files       []FileDigest `json:"files"`
	Warnings    []string     `json:"warnings,omitempty"`
}

type Host struct {
	Hostname     string `json:"hostname"`
	Distribution string `json:"distribution"`
	Version      string `json:"version"`
	Kernel       string `json:"kernel"`
	Architecture string `json:"architecture"`
	BootID       string `json:"boot_id,omitempty"`
}

type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Service struct {
	Name    string `json:"name"`
	Active  string `json:"active"`
	Enabled string `json:"enabled"`
}

type Account struct {
	Name  string `json:"name"`
	UID   int    `json:"uid"`
	GID   int    `json:"gid"`
	Shell string `json:"shell"`
}

type Listener struct {
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Process  string `json:"process,omitempty"`
}

type FileDigest struct {
	Path   string `json:"path"`
	Exists bool   `json:"exists"`
	SHA256 string `json:"sha256,omitempty"`
	Mode   string `json:"mode,omitempty"`
	UID    int    `json:"uid,omitempty"`
	GID    int    `json:"gid,omitempty"`
}

type Change struct {
	Category string `json:"category"`
	Key      string `json:"key"`
	Kind     string `json:"kind"`
	Before   string `json:"before,omitempty"`
	After    string `json:"after,omitempty"`
	Severity string `json:"severity"`
}

type Diff struct {
	Schema      string    `json:"schema"`
	BaselineAt  time.Time `json:"baseline_at"`
	CurrentAt   time.Time `json:"current_at"`
	HostChanged bool      `json:"host_changed"`
	Changes     []Change  `json:"changes"`
}

func (s Snapshot) Validate() error {
	if s.Schema != Schema {
		return fmt.Errorf("неподдерживаемая схема snapshot %q", s.Schema)
	}
	if s.CapturedAt.IsZero() || s.Host.Hostname == "" {
		return errors.New("snapshot не содержит обязательные host/captured_at")
	}
	return nil
}

func Compare(baseline, current Snapshot) (Diff, error) {
	if err := baseline.Validate(); err != nil {
		return Diff{}, fmt.Errorf("baseline: %w", err)
	}
	if err := current.Validate(); err != nil {
		return Diff{}, fmt.Errorf("current: %w", err)
	}
	diff := Diff{Schema: "bastionctl.diff.v1", BaselineAt: baseline.CapturedAt, CurrentAt: current.CapturedAt, Changes: make([]Change, 0)}
	if baseline.Host.Hostname != current.Host.Hostname || baseline.Host.Architecture != current.Host.Architecture {
		diff.HostChanged = true
		diff.Changes = append(diff.Changes, Change{Category: "host", Key: "identity", Kind: "changed", Before: baseline.Host.Hostname + "/" + baseline.Host.Architecture, After: current.Host.Hostname + "/" + current.Host.Architecture, Severity: "critical"})
	}
	if baseline.Host.Kernel != current.Host.Kernel {
		diff.Changes = append(diff.Changes, Change{Category: "host", Key: "kernel", Kind: "changed", Before: baseline.Host.Kernel, After: current.Host.Kernel, Severity: "info"})
	}
	compareStringMaps(&diff, "package", packagesMap(baseline.Packages), packagesMap(current.Packages), "medium")
	compareStringMaps(&diff, "service", servicesMap(baseline.Services), servicesMap(current.Services), "high")
	compareStringMaps(&diff, "account", accountsMap(baseline.Accounts), accountsMap(current.Accounts), "high")
	compareStringMaps(&diff, "listener", listenersMap(baseline.Listeners), listenersMap(current.Listeners), "high")
	compareStringMaps(&diff, "managed-file", filesMap(baseline.Files), filesMap(current.Files), "critical")
	sort.Slice(diff.Changes, func(i, j int) bool {
		if diff.Changes[i].Category == diff.Changes[j].Category {
			return diff.Changes[i].Key < diff.Changes[j].Key
		}
		return diff.Changes[i].Category < diff.Changes[j].Category
	})
	return diff, nil
}

func compareStringMaps(diff *Diff, category string, before, after map[string]string, severity string) {
	keys := map[string]struct{}{}
	for key := range before {
		keys[key] = struct{}{}
	}
	for key := range after {
		keys[key] = struct{}{}
	}
	for key := range keys {
		oldValue, hadOld := before[key]
		newValue, hasNew := after[key]
		switch {
		case !hadOld && hasNew:
			diff.Changes = append(diff.Changes, Change{Category: category, Key: key, Kind: "added", After: newValue, Severity: severity})
		case hadOld && !hasNew:
			diff.Changes = append(diff.Changes, Change{Category: category, Key: key, Kind: "removed", Before: oldValue, Severity: severity})
		case oldValue != newValue:
			diff.Changes = append(diff.Changes, Change{Category: category, Key: key, Kind: "changed", Before: oldValue, After: newValue, Severity: severity})
		}
	}
}

func packagesMap(values []Package) map[string]string {
	result := make(map[string]string, len(values))
	for _, value := range values {
		result[value.Name] = value.Version
	}
	return result
}

func servicesMap(values []Service) map[string]string {
	result := make(map[string]string, len(values))
	for _, value := range values {
		result[value.Name] = value.Active + "/" + value.Enabled
	}
	return result
}

func accountsMap(values []Account) map[string]string {
	result := make(map[string]string, len(values))
	for _, value := range values {
		result[value.Name] = strconv.Itoa(value.UID) + ":" + strconv.Itoa(value.GID) + ":" + value.Shell
	}
	return result
}

func listenersMap(values []Listener) map[string]string {
	result := make(map[string]string, len(values))
	for _, value := range values {
		key := value.Protocol + ":" + value.Address + ":" + strconv.Itoa(value.Port)
		result[key] = value.Process
	}
	return result
}

func filesMap(values []FileDigest) map[string]string {
	result := make(map[string]string, len(values))
	for _, value := range values {
		if !value.Exists {
			result[value.Path] = "missing"
			continue
		}
		result[value.Path] = strings.Join([]string{value.SHA256, value.Mode, strconv.Itoa(value.UID), strconv.Itoa(value.GID)}, ":")
	}
	return result
}
