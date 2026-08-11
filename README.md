# Secure Linux Wizard

Interactive, reversible Linux-server hardening with Russian and English interfaces.

Интерактивное и обратимое усиление безопасности Linux-сервера с русским и английским интерфейсами.

> [!CAUTION]
> No script can guarantee absolute security. Create a VPS snapshot, verify the provider recovery console, and keep the current SSH session open until a second key-based login works.
>
> Ни один скрипт не гарантирует абсолютную безопасность. Сделайте snapshot VPS, проверьте аварийную консоль провайдера и не закрывайте текущую SSH-сессию до успешного второго входа по ключу.

## Documentation / Документация

- [Русская инструкция](README_RU.md)
- [English guide](README_EN.md)
- [Security policy / Сообщить об уязвимости](SECURITY.md)
- [Release checklist / Выпуск релиза](RELEASE_CHECKLIST.md)
- [GitHub publishing guide / Публикация на GitHub](docs/PUBLISH_GITHUB_RU.md)

## Quick start / Быстрый старт

Audit first / Сначала аудит:

```bash
sudo bash secure-linux-wizard.sh --audit --lang ru
```

Safe preview / Безопасный предварительный просмотр:

```bash
sudo bash secure-linux-wizard.sh --role server --lang ru --dry-run
```

Interactive server setup / Интерактивная настройка сервера:

```bash
sudo bash secure-linux-wizard.sh --role server --lang ru
```

Windows Admin's PC helper / Помощник для Windows:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\secure-linux-admin.ps1 -Language ru
```

The wizard never auto-reboots and never disables password/root SSH until a second key login is confirmed. Docker/VPN routing and application-specific policies are intentionally not rewritten blindly.

Мастер не перезагружает сервер автоматически и не отключает парольный/root SSH до подтверждения второго входа по ключу. Сети Docker/VPN и правила конкретных приложений намеренно не переписываются вслепую.

## Supported baseline / Поддерживаемая база

- Ubuntu Server 22.04/24.04 and Debian 12/13: primary path;
- Fedora/RHEL-like systems with `dnf`, `firewalld`, and `systemd`: conservative baseline;
- Windows 10/11 PowerShell 5.1+, Linux, macOS, or WSL for Admin's PC.

## Verification / Проверка

```bash
bash tests/smoke.sh
```

GitHub Actions also checks Bash syntax, ShellCheck warnings, bilingual dry-runs, rollback path validation, checksum integrity, and PowerShell parsing.

## Source and license / Источник и лицензия

The design is adapted from [How To Secure A Linux Server](https://github.com/imthenachoman/How-To-Secure-A-Linux-Server) by Anchal Nigam. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). This project is shared under [CC BY-SA 4.0](LICENSE.txt) with no warranty.

Архитектура адаптирована из руководства [How To Secure A Linux Server](https://github.com/imthenachoman/How-To-Secure-A-Linux-Server) Анчала Нигама. Подробности — в [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Проект распространяется по [CC BY-SA 4.0](LICENSE.txt) без гарантий.
