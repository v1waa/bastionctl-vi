# Contributing

Contributions in Russian or English are welcome.

## Before changing security defaults

- explain the threat being addressed;
- describe compatibility risks for SSH, Docker, VPN, IPv4/IPv6 forwarding, and recovery consoles;
- prefer a reversible drop-in over editing a vendor file;
- preserve staged SSH lockdown and automatic validation;
- never add a private key, token, `.env`, real server address, or unredacted log.

## Local checks

```bash
bash tests/smoke.sh
shellcheck -S warning secure-linux-wizard.sh secure-linux-wizard-ru.sh secure-linux-wizard-en.sh
```

On Windows, parse the helper without running it:

```powershell
$tokens = $null
$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile(
  (Resolve-Path .\secure-linux-admin.ps1),
  [ref]$tokens,
  [ref]$errors
) | Out-Null
$errors
```

Run real server changes only on a disposable VPS with a provider snapshot and recovery-console access. Do not test destructive scenarios on a production server.

## Pull requests

Document:

- what changed;
- which distributions and PowerShell versions were tested;
- whether SSH, firewall, Docker/VPN, reboot, or rollback behavior changed;
- how to recover if the change fails.

Adaptations remain under CC BY-SA 4.0 and must retain the attribution in `THIRD_PARTY_NOTICES.md`.
