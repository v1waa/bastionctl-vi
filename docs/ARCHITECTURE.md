# Архитектура

## Цели

Главный приоритет — простая поддержка и сборка:

- один Go-модуль и один исполняемый файл на платформу;
- только стандартная библиотека;
- OpenSSH вместо собственного сетевого протокола;
- локальное файловое хранилище вместо базы данных;
- постоянный агент на сервере отсутствует;
- явные платформенные границы и версионированные JSON-схемы.
- при росте ответственности предпочтительна переработка связной границы
  пакета, а не добавление локального workaround в существующий поток.

## Компоненты

| Пакет | Ответственность |
|---|---|
| `cmd/bastionctl` | entry point, сигналы, версия сборки |
| `internal/cli` | команды, параметры, коды завершения, JSON/text |
| `internal/console` | реестр действий панели, сценарии и подтверждения |
| `internal/tui` | адаптивный layout, mouse/keyboard events и terminal lifecycle |
| `internal/controller` | реестр, установка, пользователи, reset, история, snapshots |
| `internal/state` | атомарное локальное хранилище и подписи Ed25519 |
| `internal/config` | строгий TOML subset, defaults, validation, rendering |
| `internal/profile` | встроенные стартовые политики сервисов |
| `internal/admin` | диагностика, проверка target, безопасные `ssh`/`scp` |
| `internal/server` | Linux-контроли, preflight, apply, backup/rollback |
| `internal/sshkey` | единая проверка usernames, Ed25519-ключей и fingerprints |
| `internal/inventory` | snapshot и детерминированный drift diff |
| `internal/explain` | назначение, риск, проверка и откат контролей |
| `internal/report` | `bastionctl.report.v1` и renderers |

Non-Linux-сборки содержат полный режим администратора. Server `apply` на них
явно отклоняется. Linux-сборка содержит оба режима.

## Поток управления

```mermaid
flowchart LR
    T[TUI: mouse / arrows / number] --> UI[Console command registry]
    UI --> C[Controller]
    CLI[CLI] --> C
    C --> S[(Local state)]
    C --> A[Admin transport]
    A -->|OpenSSH| R[Server mode via sudo -n]
    R --> P[Preflight + controls]
    R --> I[Inventory snapshot]
    R --> U[Key-only user creation]
    R --> X[Owned-policy reset]
    I --> A
    A --> C
    C -->|sign, history, diff| S
```

## Интерактивный терминал

`internal/console` больше не хранит отдельные копии пунктов в печатной таблице
и в `switch`. Один реестр команд содержит номер, подпись, смысловую группу,
совместимые текстовые алиасы и обработчик. Из него одновременно строятся
кликабельное меню и line-mode fallback.

`internal/tui` не знает о серверах или контролях. Он получает только список
опций, группирует их в три, два или один столбец по размеру терминала и
возвращает выбранный ID. На Linux/macOS terminal mode сохраняется и временно
переключается через системный `stty`; на Windows используются Console API и VT
input. Mouse reporting и alternate screen активны только внутри `Select`.
Перед вызовом обработчика состояние восстанавливается через `defer`, поэтому
OpenSSH, `sudo`, `passwd` и обычные вопросы всегда получают нормальный TTY.

При pipe, тестовом `io.Reader` или неподдерживаемом terminal mode `Select`
ничего не меняет и сообщает консоли использовать текстовый fallback. Таким
образом mouse UI является дополнительным способом управления, а не новой
обязательной зависимостью.

Реестр хранит connection metadata и путь к управляемой политике, но не пароли.
`Identity` — только путь к закрытому ключу. Для password bootstrap отдельный
Ed25519-ключ создаётся внутри защищённого state-каталога; его содержимое читает
только OpenSSH.

## Жизненный цикл apply

```mermaid
flowchart TD
    A[Validate config and platform] --> B[Acquire process lock]
    B --> C[Preflight every enabled control]
    C -->|blocked| D[Report; no configuration changes]
    C -->|passed| E[Packages and system controls]
    E --> F[Validate and reload SSH]
    F -->|failed| G[Restore SSH; stop]
    F -->|passed| H[Read-only security checks]
    H --> I[Add SSH allow; enable UFW last]
```

Порядок контролей фиксирован в исходном коде. Ошибка останавливает следующие
контроли. Firewall стоит последним, поэтому сбой пакетов, validators, прав, SSH
или Fail2ban не может завершиться включением firewall.

Интерактивный контроллер дополнительно выполняет отдельный `plan` и требует
точную строку `APPLY <server-id>`. Низкоуровневый CLI требует `--yes`, чтобы
оставаться пригодным для автоматизации.

## Жизненный цикл reset

```mermaid
flowchart TD
    A[reset-plan: inspect allowlist] --> B[Exact RESET confirmation]
    B --> C[Root lock + backup directory]
    C --> D[Check first-line ownership marker]
    D -->|foreign or missing| E[Preserve and report]
    D -->|owned| F[Remove one drop-in]
    F --> G[Validate and activate remaining config]
    G -->|failed| H[Restore that file]
    G -->|passed| I[Next file]
    I --> J[Delete safe tagged UFW rules, descending]
```

Reset не пытается реконструировать неизвестное состояние ОС до установки.
Пакеты, shared service state, UFW enable/default policy, аккаунты,
`authorized_keys`, home и данные приложений остаются неизменными. Это делает
операцию идемпотентной и ограничивает область записи явным allowlist.
При active UFW с deny/reject incoming помеченный SSH allow сохраняется: reset
не должен превращать отмену hardening в потерю управления сервером.

## Создание пользователя

Публичный ключ нормализуется на admin-ПК и повторно на сервере. Версионированный
JSON `bastionctl.user-add.v1` передаётся через stdin фиксированной sudo-команды,
поэтому username и ключ не расширяют sudo command line. Сервер допускает только
UID >= 1000, обычный home без symlink и login shell. `.ssh` открывается как
каталог с `O_NOFOLLOW`; `authorized_keys` открывается относительно descriptor
через `openat`, блокируется, проверяется и только дополняется. Закрытый ключ в
этот поток не входит.

Роль sudo опциональна. После добавления группы пароль задаётся отдельным
интерактивным `sudo passwd`; его байты остаются между терминалом, OpenSSH и
удалёнными `sudo`/`passwd`.

## Модель изменения файлов

Для каждого управляемого серверного файла:

1. отклоняется symlink target или parent component;
2. существующий regular file копируется в run-specific backup;
3. same-directory temporary file получает явные owner/mode;
4. данные синхронизируются и атомарно переименовываются;
5. выполняются validator и activation command;
6. при ошибке восстанавливается прежний файл.

Установка пакетов, исправление metadata и правила UFW честно отмечаются как
нетранзакционные операции. Reset сохраняет исходный numbered status UFW перед
удалением помеченных правил и сообщает частичный результат при ошибке.

## SSH и bootstrap

Target имеет строгий формат `user@host`; port и identity проверяются до запуска.
Пользовательские данные не превращаются в local shell. Удалённая команда
состоит из фиксированных токенов с POSIX quoting и обычно выполняется через
`sudo -n`; интерактивная установка использует удалённый TTY и штатный `sudo`.

Host-key policy по умолчанию — `StrictHostKeyChecking=yes`. Явный relaxed mode
для готового ключа использует только `accept-new`, никогда не принимает
изменившийся ключ. Password bootstrap вместо этого использует `ask`: оператор
должен независимо сверить показанный fingerprint до ответа `yes` и ввода
пароля. После тестового входа новым ключом policy становится строгой.

Installer сначала определяет `uname -m`, проверяет ELF class/machine выбранного
бинарника, загружает файлы во временные случайные пути, сверяет SHA-256, проверяет
sudoers через `visudo -cf`, затем устанавливает root-owned файлы. Первый вход
может установить ключ существующему пользователю либо при входе от root создать
непривилегированного администратора. Пароли обрабатывают только OpenSSH,
удалённый `passwd` и `sudo`; приложение не получает их байты. В sudoers также
перечислены точные `reset-plan`, `reset` и `user-add`; переменный запрос
`user-add` поступает только через stdin.

## Локальное состояние

Файлы реестра, политик, истории и snapshots пишутся через temporary + sync +
rename; final symlink отклоняется. `config_path` реестра обязан указывать на
ожидаемый файл внутри выбранного state root.

Snapshot подписывается локальным Ed25519-ключом. При чтении проверяются и
signature, и совпадение embedded public key с локально доверенным ключом. Это
обнаруживает случайную/частичную подмену, но не защищает от атакующего, который
полностью контролирует аккаунт администратора и украл private key.

## Совместимость

Модуль объявляет Go 1.22. Release-сборки используют `CGO_ENABLED=0`, не имеют
внешних модулей и создаются для Linux amd64/arm64, Windows amd64, macOS
amd64/arm64. Серверные контроли рассчитаны на поддерживаемые Debian/Ubuntu с
apt и systemd.
