# Security model

## Assumptions

- The server starts from a vendor-maintained Debian or Ubuntu image.
- The operator controls either an existing non-root sudo account with a valid
  public-key login or the initial root/non-root SSH password issued for a new
  host, plus the provider console and a recoverable backup.
- Root-owned configuration directories have not already been compromised.
- Distribution package repositories and signing configuration are trusted.
- The administrator verifies the initial SSH host-key fingerprint through an
  independent channel.

## Safety properties

- `audit`, `plan`, `snapshot`, `reset-plan`, `workload xhttp plan`, and
  `workload xhttp verify` are read-only.
- `apply` requires Linux, root, an explicit `--yes`, a supported platform, and
  an exclusive process lock.
- Every enabled control completes preflight before configuration changes begin.
- Public-key-only SSH changes require a real authorized key, safe path
  permissions, and a sudo-capable non-root administrator.
- SSH is validated with `sshd -t` and effective `sshd -T` values before reload.
- A failed SSH validation or reload restores the prior drop-in and stops before
  the firewall control.
- The current remote client and server port are checked against the intended
  firewall policy.
- Administrator mode uses strict host-key checking by default, batch mode,
  validated targets, and fixed remote command arguments.
- The explicitly selected password bootstrap is the only non-batch exception.
  It requires a character-device terminal, disables public-key authentication,
  uses OpenSSH's own password prompt, and sets host-key checking to `ask` so the
  operator can verify the fingerprint before sending a password. On success it
  tests the new key and permanently returns that server policy to strict mode.
- A root bootstrap creates or reuses a non-UID-0 administrator, installs only
  the generated public key, adds the account to Debian/Ubuntu's `sudo` group,
  and lets the remote `passwd` program collect an account password directly.
  If sudo is absent, this explicit bootstrap may install the signed distribution
  package through the host's already configured apt repositories.
- Remote installation verifies server architecture, local ELF metadata and
  SHA-256 after upload; a sudoers policy is validated with `visudo -cf` before
  root-owned installation.
- `user-add` accepts a versioned JSON request through stdin of one fixed sudo
  command. Both sides validate the conservative username and Ed25519 key. The
  server opens `.ssh` and `authorized_keys` with no-follow semantics, checks
  ownership and UID >= 1000, locks the file, and appends without replacing
  existing keys. The private key never enters the application or server.
- `reset` requires a separate plan and explicit confirmation. It uses a fixed
  allowlist, checks the first-line `Managed by bastionctl` marker before file
  removal, backs up each file, validates/activates the remaining configuration,
  and deletes only UFW rules carrying a bastionctl comment. A tagged SSH allow
  is retained when active deny/reject defaults could otherwise lock out the
  operator. Reset never traverses or deletes user homes, application data,
  accounts, or authorized keys.
- Managed files reject symbolic links, use same-directory atomic replacement,
  preserve backups, and sync file-system metadata before reporting success.
- Firewall rules preserve access by adding SSH allows before default-deny and
  activation commands.
- Local registry/config/history writes are atomic and reject final symlinks.
  Snapshot signatures are checked against the locally trusted Ed25519 key, not
  only against a public key embedded in the snapshot.
- Mouse input is reduced to a validated menu ID through bounded SGR sequence
  parsing and fixed hitboxes. The temporary raw/VT terminal state and mouse
  reporting are disabled before any prompt, OpenSSH process, or command
  handler runs; redirected input uses the unchanged line-mode path.
- XHTTP setup requires a separate server-side preflight and explicit `--yes`.
  It checks exact DNS A/AAAA results, supported OS/architecture, minimum
  capacity, free listeners, UFW default-deny plus TCP 80/443, and rejects an
  existing 3x-ui installation without a bastionctl ownership marker.
- The 3x-ui release tag and amd64/arm64 SHA-256 values are fixed in source.
  Download redirects remain on an HTTPS host allowlist, archive/download sizes
  are bounded, and extraction rejects traversal, symlinks, hardlinks and
  special files before any release file is installed as root.
- The 3x-ui panel is configured on `127.0.0.1` only. Its random initial
  credentials are generated on the server, stored as 0600 below a 0700
  root-only workload directory, omitted from JSON reports, and intended for
  deletion after SSH-tunnel login and 2FA enrollment. The panel port is never
  added to UFW.
- The base SSH policy keeps global TCP forwarding disabled. The XHTTP desired
  state adds one `Match User` exception for the managed administrator with
  `AllowTcpForwarding local` and exact loopback-only `PermitOpen`. Effective
  configuration is checked for both that administrator and a nonmatching user.
- Certificates are obtained with the distribution Certbot package. The
  resulting certificate hostname, validity window, archive path and private-key
  owner/mode are checked before service activation.
- The x-ui database and log directories are root-owned and hidden from other
  users. A separate managed systemd drop-in applies a restrictive umask,
  `NoNewPrivileges`, private temporary storage, protected home/kernel/control
  groups, and `RestrictSUIDSGID`; effective properties are verified after start.
  A root-only managed environment file fixes the SQLite backend and prevents an
  unrelated pre-existing `/etc/default/x-ui` from silently changing database
  behavior.

## Trust boundaries

The local server binary runs as root during `apply`, `reset`, and `user-add` and
therefore belongs to the trusted computing base. The admin binary delegates
transport and host-key
verification to the locally installed OpenSSH Client. JSON returned over that
authenticated channel is schema-validated before display.

The administrator workstation and its user account are a trust boundary. The
local state directory contains server addresses, policy, report history, a
snapshot integrity key, and any dedicated passwordless Ed25519 private keys
created by the bootstrap wizard. It never contains login or sudo passwords.
Generated keys and state files use restrictive permissions, but this does not
protect them from malware running as the same administrator user; protect and
back up the workstation accordingly.

Package installation trusts the configured distribution repositories. Service
validators (`sshd`, `apt-config`, `augenrules`, `fail2ban-client`, `systemctl`,
and `sysctl`) remain authoritative for their own configuration formats.
The pinned upstream 3x-ui/Xray binaries are an additional trusted component for
the optional XHTTP workload. SHA-256 proves that fetched bytes match the
reviewed release metadata; it does not independently prove upstream code safe.

## Explicit non-goals

This release does not remediate an already-rooted host, manage application
secrets, prove backup recovery, change provider firewalls, enable disk
encryption, rotate keys, or force Docker-published ports through UFW. It does
not delete existing users, packages, services, untagged firewall rules, home
directories, or service data. Reset is removal of bastionctl-owned policy, not
an operating-system factory reset. It is a baseline hardening assistant, not a
compliance attestation.

The XHTTP wizard does not buy domains, edit provider firewalls, create 3x-ui
inbounds or client UUIDs, enroll panel 2FA, configure a client, test censorship
resistance, or promise that one XHTTP mode works on every network. It provides
concrete manual instructions and verifies observable server state. Base-policy
reset does not remove the optional workload, certificates or its data because
those belong to a separate service ownership boundary and may be user data.
Reset does remove the narrow tunnel exception together with the common managed
SSH drop-in, leaving the still-installed panel unreachable from the network
until the base policy is applied again.

The application never collects an interactive sudo password. When requested,
it allocates an SSH TTY and the remote `sudo` program reads the password itself.
The generated ongoing policy grants only exact bastionctl
audit/plan/apply/snapshot/reset-plan/reset/user-add commands. The variable
user-add request travels through stdin rather than sudo command arguments. The
optional XHTTP module adds only exact `workload xhttp plan/apply/verify`
commands; its non-secret desired state also travels through stdin.
Replacing the root-owned executable remains outside that policy and can require
another interactive sudo prompt.

## Failure and rollback limits

Managed text files have per-control backups and rollback. Package installation,
file metadata corrections, runtime sysctl transitions, service enablement, and
UFW rule additions may have effects that cannot be transactionally reversed.
The engine stops on the first apply failure, reports the backup directory, and
never proceeds to firewall after an earlier failure.

XHTTP apply backs up and restores only its fixed managed paths and prior service
state. Distribution packages and Certbot/Let's Encrypt state are shared and are
not automatically removed on rollback; the report states this limit. A manual
inbound created after installation is service data and is not modified by the
base hardening reset.

Reset deliberately preserves packages, shared service enablement, UFW
enable/default policy, user accounts, and keys because their pre-bastionctl
ownership cannot be proved. Removing the sysctl drop-in and running
`sysctl --system` cannot reset a key that has no remaining source; a planned
reboot is the authoritative boundary for those runtime-only values. A partial
UFW deletion failure is reported with the pre-reset numbered status saved in
the backup directory.

## Reporting a vulnerability

Do not include private keys, passwords, tokens, server addresses, complete
configuration dumps, or unredacted logs. Provide the smallest safe reproducer,
the affected version, platform, action, and control name.
