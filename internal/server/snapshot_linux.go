//go:build linux

package server

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"bastionctl/internal/config"
	"bastionctl/internal/inventory"
)

func capturePlatform(ctx context.Context, _ config.Config, version, configPath string) (inventory.Snapshot, error) {
	distro := readDistribution()
	hostname, err := os.Hostname()
	if err != nil {
		return inventory.Snapshot{}, err
	}
	snapshot := inventory.Snapshot{
		Schema: inventory.Schema, ToolVersion: version, CapturedAt: time.Now().UTC(),
		Host:     inventory.Host{Hostname: hostname, Distribution: distro.PrettyName, Version: distro.VersionID, Architecture: runtime.GOARCH},
		Packages: []inventory.Package{}, Services: []inventory.Service{}, Accounts: []inventory.Account{},
		Listeners: []inventory.Listener{}, Files: []inventory.FileDigest{}, Warnings: []string{},
	}
	if result := runCommand(ctx, "", "uname", "-r"); result.Err == nil {
		snapshot.Host.Kernel = result.Stdout
	} else {
		snapshot.Warnings = append(snapshot.Warnings, "uname -r: "+firstError(result))
	}
	if data, readErr := os.ReadFile("/proc/sys/kernel/random/boot_id"); readErr == nil {
		snapshot.Host.BootID = strings.TrimSpace(string(data))
	}
	capturePackages(ctx, &snapshot)
	captureServices(ctx, &snapshot)
	captureAccounts(&snapshot)
	captureListeners(ctx, &snapshot)
	paths := []string{
		configPath,
		"/etc/ssh/sshd_config",
		"/etc/ssh/sshd_config.d/00-bastionctl.conf",
		"/etc/sysctl.d/99-bastionctl.conf",
		"/etc/systemd/journald.conf.d/60-bastionctl.conf",
		"/etc/audit/rules.d/60-bastionctl.rules",
		"/etc/fail2ban/jail.d/sshd-bastionctl.local",
		"/etc/apt/apt.conf.d/52bastionctl-unattended-upgrades",
		"/etc/ufw/user.rules",
		"/etc/ufw/user6.rules",
	}
	seen := map[string]struct{}{}
	for _, path := range paths {
		if path == "" {
			continue
		}
		if _, exists := seen[path]; exists {
			continue
		}
		seen[path] = struct{}{}
		snapshot.Files = append(snapshot.Files, digestFile(path))
	}
	sort.Slice(snapshot.Packages, func(i, j int) bool { return snapshot.Packages[i].Name < snapshot.Packages[j].Name })
	sort.Slice(snapshot.Services, func(i, j int) bool { return snapshot.Services[i].Name < snapshot.Services[j].Name })
	sort.Slice(snapshot.Accounts, func(i, j int) bool { return snapshot.Accounts[i].Name < snapshot.Accounts[j].Name })
	sort.Slice(snapshot.Listeners, func(i, j int) bool {
		left := fmt.Sprintf("%s:%s:%05d", snapshot.Listeners[i].Protocol, snapshot.Listeners[i].Address, snapshot.Listeners[i].Port)
		right := fmt.Sprintf("%s:%s:%05d", snapshot.Listeners[j].Protocol, snapshot.Listeners[j].Address, snapshot.Listeners[j].Port)
		return left < right
	})
	sort.Slice(snapshot.Files, func(i, j int) bool { return snapshot.Files[i].Path < snapshot.Files[j].Path })
	return snapshot, nil
}

func capturePackages(ctx context.Context, snapshot *inventory.Snapshot) {
	result := runCommand(ctx, "", "dpkg-query", "-W", "-f=${binary:Package}\t${Version}\n")
	if result.Err != nil {
		snapshot.Warnings = append(snapshot.Warnings, "dpkg-query: "+firstError(result))
		return
	}
	for _, line := range strings.Split(result.Stdout, "\n") {
		name, version, found := strings.Cut(line, "\t")
		if found && name != "" {
			snapshot.Packages = append(snapshot.Packages, inventory.Package{Name: name, Version: version})
		}
	}
}

func captureServices(ctx context.Context, snapshot *inventory.Snapshot) {
	units := []string{"ssh.service", "sshd.service", "ufw.service", "fail2ban.service", "unattended-upgrades.service", "auditd.service", "apparmor.service", "chrony.service", "systemd-journald.service"}
	for _, unit := range units {
		active := runCommand(ctx, "", "systemctl", "is-active", unit)
		enabled := runCommand(ctx, "", "systemctl", "is-enabled", unit)
		activeState := active.Stdout
		if activeState == "" {
			activeState = "unknown"
		}
		enabledState := enabled.Stdout
		if enabledState == "" {
			enabledState = "unknown"
		}
		snapshot.Services = append(snapshot.Services, inventory.Service{Name: unit, Active: activeState, Enabled: enabledState})
	}
}

func captureAccounts(snapshot *inventory.Snapshot) {
	file, err := os.Open("/etc/passwd")
	if err != nil {
		snapshot.Warnings = append(snapshot.Warnings, "/etc/passwd: "+err.Error())
		return
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) < 7 {
			continue
		}
		uid, uidErr := strconv.Atoi(fields[2])
		gid, gidErr := strconv.Atoi(fields[3])
		if uidErr == nil && gidErr == nil {
			snapshot.Accounts = append(snapshot.Accounts, inventory.Account{Name: fields[0], UID: uid, GID: gid, Shell: fields[6]})
		}
	}
	if err := scanner.Err(); err != nil {
		snapshot.Warnings = append(snapshot.Warnings, "/etc/passwd: "+err.Error())
	}
}

func captureListeners(ctx context.Context, snapshot *inventory.Snapshot) {
	result := runCommand(ctx, "", "ss", "-H", "-lntup")
	if result.Err != nil {
		snapshot.Warnings = append(snapshot.Warnings, "ss: "+firstError(result))
		return
	}
	for _, line := range strings.Split(result.Stdout, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		port, ok := trailingPort(fields[4])
		if !ok {
			continue
		}
		address := fields[4][:strings.LastIndex(fields[4], ":")]
		address = strings.Trim(address, "[]")
		process := ""
		if len(fields) > 6 {
			process = strings.Join(fields[6:], " ")
		}
		snapshot.Listeners = append(snapshot.Listeners, inventory.Listener{Protocol: fields[0], Address: address, Port: port, Process: process})
	}
}

func digestFile(path string) inventory.FileDigest {
	result := inventory.FileDigest{Path: path}
	info, err := os.Lstat(path)
	if err != nil {
		return result
	}
	result.Exists = true
	result.Mode = fmt.Sprintf("%04o", info.Mode().Perm())
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		result.UID = int(stat.Uid)
		result.GID = int(stat.Gid)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		result.Mode = "symlink"
		return result
	}
	if !info.Mode().IsRegular() {
		return result
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return result
	}
	digest := sha256.Sum256(data)
	result.SHA256 = hex.EncodeToString(digest[:])
	return result
}
