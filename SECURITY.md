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

- `audit` and `plan` are read-only.
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
- Managed files reject symbolic links, use same-directory atomic replacement,
  preserve backups, and sync file-system metadata before reporting success.
- Firewall rules preserve access by adding SSH allows before default-deny and
  activation commands.
- Local registry/config/history writes are atomic and reject final symlinks.
  Snapshot signatures are checked against the locally trusted Ed25519 key, not
  only against a public key embedded in the snapshot.

## Trust boundaries

The local server binary runs as root during `apply` and therefore belongs to the
trusted computing base. The admin binary delegates transport and host-key
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

## Explicit non-goals

This release does not remediate an already-rooted host, manage application
secrets, prove backup recovery, change provider firewalls, enable disk
encryption, rotate keys, or force Docker-published ports through UFW. It does
not delete existing users, packages, services, or firewall rules. It is a
baseline hardening assistant, not a compliance attestation.

The application never collects an interactive sudo password. When requested,
it allocates an SSH TTY and the remote `sudo` program reads the password itself.
The generated ongoing policy grants only the exact bastionctl
audit/plan/apply/snapshot commands. Replacing the root-owned executable remains
outside that policy and can require another interactive sudo prompt.

## Failure and rollback limits

Managed text files have per-control backups and rollback. Package installation,
file metadata corrections, runtime sysctl transitions, service enablement, and
UFW rule additions may have effects that cannot be transactionally reversed.
The engine stops on the first apply failure, reports the backup directory, and
never proceeds to firewall after an earlier failure.

## Reporting a vulnerability

Do not include private keys, passwords, tokens, server addresses, complete
configuration dumps, or unredacted logs. Provide the smallest safe reproducer,
the affected version, platform, action, and control name.
