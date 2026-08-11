# Third-party notices and design record

## Primary source

This package was designed from and adapted to automate selected recommendations in:

- **How To Secure A Linux Server**
- Author: **Anchal Nigam** (`imthenachoman`)
- Repository: <https://github.com/imthenachoman/How-To-Secure-A-Linux-Server>
- Source license: **Creative Commons Attribution-ShareAlike 4.0 International**
- License: <https://creativecommons.org/licenses/by-sa/4.0/>
- Reviewed: **2026-08-10**
- Reviewed README blob: `5e9de5137a1f6c2647755029b354aa1fd0c6c723`
- Reviewed sysctl reference blob: `0c26184928b45caeb5ef9e8833aa2d420a48a791`

The upstream author and contributors do not endorse this package. Errors in the automation, translations, defaults, or documentation belong to this package, not to the source guide.

## Concepts carried into this package

The package follows the guide's emphasis on:

- threat-model and recovery planning;
- keeping a second SSH terminal open;
- public-key SSH authentication;
- a restricted SSH user set;
- configuration backups before changes;
- default-deny host firewall policy;
- automatic critical/security updates;
- Fail2Ban protection;
- persistent logging, port review, and Lynis auditing;
- explicit warnings around kernel hardening and root lockout;
- verification after every security change.

The package does not reproduce the guide verbatim. The implementation, prompts, rollback format, staged SSH workflow, bilingual user interface, PowerShell helper, audit report, Docker/VPN compatibility behavior, and logs were newly written for this package.

## Material differences from the source guide

1. **OpenSSH algorithms are not pinned.** The guide contains lists based partly on older Mozilla recommendations. This package relies on maintained distribution/OpenSSH defaults and hardens authentication and access policy instead.
2. **Root is blocked only in SSH.** The package sets `PermitRootLogin no` after a verified second login. It does not run `passwd -l root`, preserving local recovery mechanisms such as `sulogin`.
3. **SSH hardening is two-phase.** Password and root SSH access remain available until the user confirms a successful key login and sudo access from another terminal.
4. **The firewall preserves existing service exposure by default.** Current public listeners are proposed as the default list, and the user can remove unneeded ports. Existing firewalld allowances are not deleted automatically.
5. **Outgoing traffic remains allowed.** A global outbound deny policy often breaks package repositories, DNS, mail, API clients, containers, and VPNs. Advanced egress filtering is left to a workload-specific policy.
6. **Routing-sensitive sysctls are excluded.** The package never changes `ip_forward`, IPv6 forwarding, `rp_filter`, NAT, or IPv6 availability. It applies only supported baseline keys and skips unwritable keys.
7. **Docker rules are not rewritten.** Docker networking can bypass UFW and is highly workload-specific. The package reports published ports and tells the user to bind internal services to loopback.
8. **High-risk or workload-specific sections remain manual.** GRUB passwords, disk encryption, AIDE initialization, CrowdSec/PSAD, application MAC profiles, mail relays, antivirus, rootkit scanners, `/proc hidepid`, default umask changes, and application sandboxing are not applied blindly.
9. **Automatic reboot is always disabled.** The package reports when a reboot is needed and leaves scheduling to the administrator.
10. **Server support is explicit.** Ubuntu/Debian is the primary path; Fedora/RHEL-like support is a conservative baseline and may require repository setup for optional tools.

## Other software invoked

The package can use software supplied by the operating system, including OpenSSH, systemd, UFW, firewalld, Fail2Ban, unattended-upgrades, dnf-automatic, auditd, Lynis, libpwquality, Docker CLI, and standard Unix/PowerShell utilities. Each remains under its own license and is installed from the user's configured distribution repositories.

## Share-alike notice

This package is shared under CC BY-SA 4.0 to preserve the source guide's attribution and share-alike conditions. If you distribute a modified version, identify your changes, keep this attribution, and license the adapted material under CC BY-SA 4.0 or a compatible license.
