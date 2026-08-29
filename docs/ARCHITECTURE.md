# Архитектура bastionctl 2.0

## Целевая модель

Версия 2.0 разделяет продукт на две явно разные роли:

```mermaid
flowchart LR
    UI["Windows desktop\nWails + WebView2"] --> CORE["Desktop core\nоперации и состояние"]
    CORE --> SSH["Встроенный SSH\nhost key + auth + PTY"]
    SSH --> CLI["Ubuntu binary\nserver mode"]
    CLI --> OS["Ubuntu controls\nSSH, UFW, updates"]
```

- Windows-приложение владеет интерфейсом, локальным реестром, историей,
  snapshots и SSH-сессиями.
- Ubuntu-бинарник является headless command runner. Он не слушает сеть и не
  работает постоянно.
- SSH остаётся единственной сетевой границей. Проприетарный agent/protocol не
  добавляется.

Будущие desktop- и server-платформы должны подключаться через новые адаптеры,
а не через условные ветки внутри контролов.

## Слои

| Слой | Пакеты | Ответственность |
|---|---|---|
| Windows shell | `cmd/bastionctl-desktop`, `internal/desktopui`, `ui/windows` | Native window, WebView2 assets, события и lifecycle |
| Desktop application | `internal/desktop` | View models, подтверждения, workflows, отсутствие секретов в state |
| Domain controller | `internal/controller`, `internal/state`, `internal/profile` | Реестр, policy, история, snapshots, orchestration |
| SSH transport | `internal/terminal`, `internal/admin` | Pinned host key, key/password auth, command transport, upload, PTY |
| Ubuntu runtime | `cmd/bastionctl`, `internal/server`, `internal/workload` | Audit/plan/apply/reset и workload controls |
| Compatibility UI | `internal/console`, `internal/tui`, `internal/cli` | Rescue/automation CLI и прежний TUI |

Desktop UI не формирует root-команды из произвольных фрагментов. Оно передаёт
типизированные запросы application layer. `internal/admin` строит фиксированные
команды, сервер повторно валидирует JSON и выполняет только известные actions.

## SSH trust и credentials

Для каждого server ID создаётся отдельный каталог:

```text
servers/<id>/
  config.toml
  id_ed25519
  id_ed25519.pub
  known_hosts
  known_hosts.previous
  workloads/
```

`known_hosts` появляется только после повторного probe и точного подтверждения
`TRUST <fingerprint>`. И встроенный клиент, и OpenSSH fallback используют этот
же файл. Изменившийся ключ блокируется; `REPLACE <fingerprint>` сохраняет
предыдущую запись перед атомарной заменой.

Пароль первого входа и passphrase передаются значениями только в активный
workflow. Они не входят в persistent structs и JSON tags, не пишутся в логи и
обнуляются в request objects после установления/завершения соединения. Go не
гарантирует физическое стирание immutable string из памяти, поэтому модель
обещает отсутствие хранения, а не невозможность memory forensics на уже
скомпрометированном ПК.

Обычная консоль и интерактивные операции используют удалённый PTY
`xterm-256color`. Для аудита и JSON-операций используется session без PTY с
ограничением ввода и вывода. Загрузки принимают только случайные пути
`/tmp/bastionctl-{bin,config,sudoers}-<24 hex>` и не могут выбрать системный
путь напрямую.

## Первый вход

```mermaid
stateDiagram-v2
    [*] --> Added
    Added --> Trusted: fingerprint + TRUST
    Trusted --> PasswordSession: одноразовый пароль
    PasswordSession --> KeyInstalled: authorized_keys
    KeyInstalled --> Verified: отдельный вход ключом
    Verified --> Managed: strict host key + bootstrap off
```

При root-bootstrap фиксированная команда создаёт непривилегированного
администратора, добавляет его в `sudo`, устанавливает ключ и при необходимости
запускает `passwd` внутри PTY. Состояние `BootstrapPending` снимается только
после нового соединения постоянным пользователем и точного проверочного вывода.

## Интерактивная установка

Установка вынесена в reusable `PreparedInstall`:

1. встроенный SSH определяет `uname -m`;
2. локальный ELF сверяется с `amd64`/`arm64`;
3. бинарник, config и sudoers получают случайные remote paths;
4. каждый файл загружается через SSH без SCP и до 100 MiB;
5. один PTY workflow запрашивает sudo-пароль, проверяет SHA-256 и `visudo`;
6. прежние root-owned файлы сохраняются во временные backups;
7. failure запускает rollback, success — version probe через новое соединение;
8. временные локальные/удалённые файлы удаляются.

CLI compatibility path использует ту же policy и прежний OpenSSH/SCP adapter.
Новые transport adapters должны реализовывать тот же подготовленный install
plan, а не копировать root-команды.

## Policy engine

Ubuntu runtime сохраняет прежнюю последовательность:

```mermaid
flowchart TD
    A["Preflight: user, key, sudo"] --> B["Backup managed paths"]
    B --> C["SSH drop-in + sshd validation"]
    C --> D["Packages and services"]
    D --> E["UFW SSH allow"]
    E --> F["UFW service ports + deny incoming"]
```

Каждый control возвращает `pass`, `fail`, `warn`, `planned`, `changed` или
`skipped`. `plan` не пишет систему. `apply` останавливается на первой ошибке.
Firewall остаётся последним контролом.

Reset работает по allowlist и ownership marker. Неизвестные файлы и
пользовательские данные не считаются принадлежащими приложению.

## Frontend

Frontend не содержит React и отдельного API-сервера. Vanilla JavaScript
вызывает Wails bindings, xterm.js отображает бинарно-совместимый терминальный
поток, а FitAddon синхронизирует rows/columns с remote PTY. Production assets
собираются Vite и встраиваются через `go:embed`.

Секретные поля имеют `type=password` и передаются только в конкретный вызов.
UI никогда не сохраняет их в localStorage/sessionStorage. Отчёты рендерятся с
HTML escaping; SSH-вывод передаётся только в xterm, а не через `innerHTML`.

## Расширение ОС

Следующие платформы добавляются отдельными командами и adapter packages:

- `cmd/bastionctl-desktop` получает platform-specific Wails/Fyne shell только
  при необходимости; application layer остаётся общим;
- `internal/server` уже разделяет Linux и unsupported implementations build
  tags;
- новый Debian/RHEL adapter должен определить package manager, services,
  firewall и валидаторы до объявления поддержки;
- формат registry/report/snapshot остаётся версионированным и мигрируется
  явно.

Правило проекта: если новая функция меняет ответственность слоя или требует
третьей условной ветки, сначала меняется граница пакета/интерфейс. Локальный
обход допускается только как временная диагностическая мера и не публикуется в
release.
