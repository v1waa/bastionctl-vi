# Secure Linux Wizard — English guide

Package version: `2026.08.10-2`

This package helps you configure a personal Linux server and its administrator's computer safely. At startup you can select:

1. `Server` — harden the server;
2. `Admin's PC` — create an SSH key and client profile on Linux, macOS, or WSL;
3. `Audit` — inspect the server without changing its configuration.

Windows users also get `secure-linux-admin.ps1`, which configures the Admin's PC, uploads the server wizard, and tests the connection.

## Important security statement

No script can guarantee “absolute security.” Security also depends on your applications, data, threat model, provider, backups, and ongoing maintenance. This wizard creates a practical, verifiable, and reversible baseline.

Before running it:

- create a VPS snapshot or full backup;
- verify access to the provider's recovery console/VNC;
- keep the current SSH session open until a second login succeeds;
- list every port genuinely required by websites, VPNs, and applications;
- make sure application data and databases have separate tested backups.

Do not run the wizard through an unreviewed `curl ... | sudo bash` command. Download the package, verify its checksums, and read this guide first.

## Source and design basis

The architecture and checks are based on Anchal Nigam's [How To Secure A Linux Server](https://github.com/imthenachoman/How-To-Secure-A-Linux-Server), reviewed on 10 August 2026. The source guide is licensed under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/).

The package preserves the guide's main principles:

- define your threat model first;
- open a second terminal before changing SSH;
- back up every configuration file before editing;
- use SSH keys and restrict access;
- use a deny-by-default firewall;
- enable security updates, Fail2Ban, persistent logs, and auditing;
- treat kernel settings and root lockout as dangerous operations;
- verify outcomes instead of merely running commands.

The wizard deliberately does not copy the guide's time-sensitive OpenSSH cipher lists. Current distribution defaults can evolve safely with updates. It also does not blindly automate the entire “Danger Zone.” See `THIRD_PARTY_NOTICES.md` for detailed attribution and differences.

## Package contents

- `secure-linux-wizard.sh` — main bilingual Bash wizard;
- `secure-linux-wizard-ru.sh` — start the Bash wizard in Russian;
- `secure-linux-wizard-en.sh` — start it in English;
- `secure-linux-admin.ps1` — Windows PowerShell helper;
- `README_RU.md` and `README_EN.md` — detailed guides;
- `THIRD_PARTY_NOTICES.md` — sources, differences, and attribution;
- `LICENSE.txt` — license;
- `SHA256SUMS.txt` — file checksums.
- `.github/workflows/ci.yml` — automated Bash and PowerShell checks;
- `tests/smoke.sh` — safe local smoke tests;
- `SECURITY.md`, `CONTRIBUTING.md`, and `CHANGELOG.md` — GitHub project metadata.

## Supported systems

Server:

- Ubuntu Server 22.04/24.04 and Debian 12/13 are the primary path;
- Fedora and RHEL-like systems with `dnf`, `firewalld`, and `systemd` have baseline support; Fail2Ban or Lynis may require an additional repository;
- OpenSSH Server and `systemd` are required;
- the selected administrator must use a real `/home/USERNAME` directory that is not a symlink or group/world-writable;
- Docker and VPNs are detected, but their networking is never rewritten automatically.

Administrator's PC:

- Windows 10/11 with Windows PowerShell 5.1+ and OpenSSH Client;
- Linux, macOS, or WSL with `bash`, `ssh`, and `ssh-keygen`;
- macOS uses Keychain, Windows uses the `ssh-agent` service, and Linux/WSL uses a user `ssh-agent`.

Use `--dry-run` first on any uncommon or heavily customized system.

## What Server mode configures

- creates or reuses a non-root administrator in `sudo`/`wheel`;
- installs that administrator's public SSH key;
- adds a dedicated OpenSSH drop-in and validates it with `sshd -t`;
- disables password/root SSH login only after a second key-based login is confirmed;
- ensures UFW or firewalld allows SSH and the selected public ports; existing allowances are preserved to avoid breaking services and are shown by the audit;
- configures a Fail2Ban SSH jail;
- enables unattended security updates without automatic reboot;
- enables compressed persistent journald storage;
- applies a compatibility-safe sysctl baseline;
- enables time synchronization;
- strengthens future local-password and basic sudo policy;
- installs auditd and Lynis when available;
- creates detailed logs and a recovery point;
- verifies critical configuration and services at the end.

It deliberately does not automatically change:

- `ip_forward`, IPv6 forwarding, `rp_filter`, NAT, or Docker Compose;
- disk encryption, GRUB, or the root account password;
- application-specific AppArmor/SELinux policies;
- CrowdSec/PSAD, AIDE databases, antivirus, or rootkit scanners;
- Nginx/Apache and application configuration;
- PostgreSQL data or application backups;
- Docker networks and container privileges;
- server reboot state.

Those areas are workload-specific and need separate testing.

## What Admin's PC mode configures

- creates an Ed25519 key with a strengthened KDF (`-a 100`);
- asks for a passphrase interactively and never records it;
- configures `ssh-agent` or Keychain;
- creates a dedicated SSH profile with `IdentitiesOnly yes`;
- optionally copies only the public `.pub` key to the server;
- tests key-based login.

`ssh-agent` is the safe way to avoid entering the passphrase for every connection. Removing the passphrase from the private key is not recommended.

## Recommended order: Windows and a VPS

### 1. Extract and verify the package

```powershell
cd "$env:USERPROFILE\Downloads\secure-linux-wizard"
Get-ChildItem
Get-FileHash .\secure-linux-wizard.sh -Algorithm SHA256
Get-Content .\SHA256SUMS.txt
```

Compare the computed hash with the matching entry in `SHA256SUMS.txt`.

### 2. Configure Admin's PC

Open a normal PowerShell window in the extracted folder:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\secure-linux-admin.ps1 -Language en
```

Select `Admin's PC` and enter:

- an alias such as `myvps`;
- the server IP address or hostname;
- the current SSH username and port;
- the suggested key path or an existing key.

Use a long, unique passphrase for a new key. Enter it once when `ssh-add` asks. The helper never sees or stores it.

If enabling Windows `ssh-agent` needs elevated rights, open a separate PowerShell window as Administrator:

```powershell
Set-Service ssh-agent -StartupType Automatic
Start-Service ssh-agent
ssh-add "$env:USERPROFILE\.ssh\myvps_ed25519"
```

Return to the normal terminal and verify:

```powershell
ssh-add -l
ssh myvps
```

### 3. Upload the Server wizard

Run the PowerShell helper again and choose `Server`, or upload manually:

```powershell
scp .\secure-linux-wizard.sh myvps:/tmp/secure-linux-wizard.sh
ssh -t myvps "sudo bash /tmp/secure-linux-wizard.sh"
```

Without an SSH profile, specify the identity explicitly:

```powershell
ssh -i "$env:USERPROFILE\.ssh\myvps_ed25519" -o IdentitiesOnly=yes USER@SERVER_IP
```

### 4. Answer the main Server questions

The wizard only asks for choices it cannot safely infer:

1. administrator username;
2. users allowed to use SSH;
3. SSH port;
4. public TCP and UDP ports;
5. trusted IP/CIDR entries for Fail2Ban;
6. whether SSH tunnels are required;
7. which baseline modules to enable.

The default public-port list comes from services that are already listening publicly, minimizing breakage. For maximum exposure reduction, remove every unnecessary port. SSH is always handled separately.

Examples:

- web server: TCP `22,80,443`, no UDP;
- web server plus WireGuard: TCP `22,80,443`, UDP `51820`;
- custom VPN: use the actual ports shown by `ss -lntup` and the VPN configuration.

Do not expose PostgreSQL `5432`, Redis `6379`, admin panels, or internal Node/Python ports to the whole internet. Bind them to `127.0.0.1`, a private VPN address, or a tightly restricted source IP.

### 5. Verify the second login before SSH lockout

When the wizard pauses, keep its terminal open. In a new PowerShell window:

```powershell
ssh myvps
whoami
sudo -v
```

Only answer `Yes` when both key login and sudo work. The wizard will then apply:

```text
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
AllowUsers ...
```

If you answer `No`, the old access method remains available. Finalize later with:

```bash
sudo secure-linux-wizard --finalize-ssh --lang en
```

### 6. Run the audit

```bash
sudo secure-linux-wizard --audit --lang en
```

The audit reports effective SSH settings, public-key fingerprints, firewall and Fail2Ban state, listening sockets, critical services, update timers, kernel/MAC status, Docker exposure, world-readable secret files without showing their contents, recent logins, and reboot status.

### 7. Reboot only when ready

The wizard never reboots automatically. If a reboot is required, first make sure the second SSH login works:

```bash
sudo reboot
```

After about a minute:

```powershell
ssh myvps
```

Then run the audit again.

## Linux/macOS/WSL as Admin's PC

```bash
chmod +x secure-linux-wizard.sh
bash secure-linux-wizard.sh --role admin --lang en
```

Upload and launch Server mode:

```bash
scp secure-linux-wizard.sh myvps:/tmp/
ssh -t myvps 'sudo bash /tmp/secure-linux-wizard.sh --role server --lang en'
```

On Linux, the wizard writes agent environment variables to `~/.local/state/secure-linux-wizard/ssh-agent.env`; source the displayed path in a new terminal. macOS uses `UseKeychain yes`.

## Preview without changes

```bash
sudo bash secure-linux-wizard.sh --role server --lang en --dry-run
```

`--dry-run` prints planned commands and managed files without installing packages or changing configuration. Always use it first on a rare or heavily customized system.

## Safe non-interactive defaults

```bash
sudo bash secure-linux-wizard.sh --role server --lang en --yes --snapshot-confirmed
```

`--yes` accepts compatibility-safe defaults but requires the explicit `--snapshot-confirmed` flag, which confirms an external snapshot and working recovery console. It never disables password/root SSH automatically. SSH finalization remains a separate key-tested action.

## Logs and recovery points

Server:

```text
/var/log/secure-linux-wizard/*.log
/root/secure-linux-wizard-backups/YYYYmmddTHHMMSSZ/
```

Windows:

```text
%LOCALAPPDATA%\SecureLinuxWizard\Logs\
```

Linux/macOS/WSL:

```text
~/.local/state/secure-linux-wizard/
```

Logs never contain private keys, key passphrases, or `.env` contents. The private key never leaves Admin's PC.

## Rollback

The wizard prints the exact command at the end. General form:

```bash
sudo secure-linux-wizard --rollback /root/secure-linux-wizard-backups/YYYYmmddTHHMMSSZ --lang en
```

Rollback restores only configuration paths changed by the wizard. It does not remove installed packages, application data, or user data. Verify afterwards:

```bash
sudo sshd -t
sudo systemctl reload ssh 2>/dev/null || sudo systemctl reload sshd
sudo ufw status verbose 2>/dev/null || sudo firewall-cmd --list-all
sudo systemctl --failed
```

If SSH is completely unavailable, use the provider recovery console and run rollback there.

## Docker and VPN warning

UFW alone does not necessarily filter Docker-published ports because Docker creates its own netfilter rules. The wizard therefore:

- never resets iptables/nftables;
- preserves forwarding, NAT, Docker bridges, and VPN routes;
- reports a warning when Docker is active;
- lists published container ports during audit.

Bind internal applications to loopback, for example:

```yaml
ports:
  - "127.0.0.1:3000:3000"
```

Keep only real VPN transport ports public and test the VPN from an external device after firewall changes.

## Troubleshooting

### `Permission denied (publickey)`

Windows:

```powershell
ssh-keygen -lf "$env:USERPROFILE\.ssh\myvps_ed25519.pub"
ssh -vv -i "$env:USERPROFILE\.ssh\myvps_ed25519" -o IdentitiesOnly=yes USER@SERVER
```

Server recovery session:

```bash
sudo ls -ld /home/USER /home/USER/.ssh
sudo ls -l /home/USER/.ssh/authorized_keys
sudo ssh-keygen -lf /home/USER/.ssh/authorized_keys
sudo sshd -T | grep -E '^(port|allowusers|pubkeyauthentication|passwordauthentication|permitrootlogin) '
```

Expected permissions are `700` for `.ssh` and `600` for `authorized_keys`, owned by that user.

### Fail2Ban does not start

```bash
sudo fail2ban-client -t
sudo systemctl status fail2ban --no-pager -l
sudo journalctl -u fail2ban -n 150 --no-pager
sudo tail -n 150 /var/log/fail2ban.log
```

The generated jail uses numeric time values and avoids expressions such as `10*60`, which older Fail2Ban releases may reject.

### A website or VPN stopped responding

```bash
sudo ss -lntup
sudo nginx -t 2>/dev/null || true
sudo docker ps --format 'table {{.Names}}\t{{.Ports}}\t{{.Status}}'
sudo ufw status numbered 2>/dev/null || sudo firewall-cmd --list-all
```

A loopback-only application should be reached through a reverse proxy. A public service needs its real transport port in the firewall, but expose it only after reviewing its authentication and patch state.

## Ongoing maintenance

Weekly:

```bash
sudo systemctl --failed
sudo fail2ban-client status sshd
sudo journalctl -p warning --since '7 days ago'
```

Monthly:

```bash
sudo apt update && apt list --upgradable       # Debian/Ubuntu
sudo dnf check-update                          # Fedora/RHEL
sudo lynis audit system
sudo secure-linux-wizard --audit --lang en
```

Regularly test backup restoration, update applications and containers, remove obsolete keys, review public ports, and follow your distribution's security advisories.
