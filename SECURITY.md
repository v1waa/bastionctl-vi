# Security policy / Политика безопасности

## Supported version / Поддерживаемая версия

Only the latest tagged release receives security fixes. / Исправления безопасности выпускаются для последнего релиза.

## Reporting a vulnerability / Сообщение об уязвимости

Do not publish exploitable details, private keys, `.env` contents, IP allowlists, server logs, or recovery archives in a public issue.

Не публикуйте в открытом issue детали эксплуатации, приватные ключи, содержимое `.env`, списки доверенных IP, серверные логи или архивы восстановления.

Use GitHub's private vulnerability-reporting feature when it is enabled:

1. open the repository's **Security** tab;
2. choose **Advisories** → **Report a vulnerability**;
3. include the affected version, operating system, safe reproduction steps, and the expected impact;
4. redact all secrets and personal server addresses.

Если private reporting ещё не включён, владелец репозитория должен открыть **Settings → Security → Advanced Security → Private vulnerability reporting** (в некоторых интерфейсах раздел ещё называется **Code security and analysis**). До этого не создавайте публичный issue с эксплуатационными подробностями.

## Scope / Область

Security reports are especially useful for:

- SSH lockout risks or authentication bypass;
- unsafe rollback paths or destructive file operations;
- secret leakage into logs;
- command or configuration injection through user input;
- firewall rules that unexpectedly expose or block services;
- insecure permissions on keys, logs, state, or recovery data.

The project provides a baseline, not a guarantee of security for third-party applications, Docker images, VPN products, or distribution packages.
