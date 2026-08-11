#!/usr/bin/env bash
#
# Secure Linux Wizard / Мастер защиты Linux
#
# Interactive, reversible baseline hardening for a personal Linux server and
# SSH setup for a Linux/macOS/WSL administrator workstation.
#
# Inspired by (not a verbatim copy of):
# https://github.com/imthenachoman/How-To-Secure-A-Linux-Server
# Upstream guide: Anchal Nigam, CC BY-SA 4.0.
# This package is distributed under CC BY-SA 4.0; see LICENSE.txt.

set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly SCRIPT_VERSION="2026.08.10-2"

LANGUAGE="${SLW_LANG:-}"
ROLE="${SLW_ROLE:-}"
ACTION="wizard"
DRY_RUN=0
ASSUME_YES=0
SNAPSHOT_CONFIRMED=0
ROLLBACK_DIR=""
CLI_ADMIN_USER=""
CLI_SSH_PORT=""
CLI_ALLOW_USERS=""

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_ID="${STAMP}-$$"
LOG_FILE=""
BACKUP_DIR=""
FILES_DIR=""
ABSENT_DIR=""
MANIFEST=""
WARNINGS_FILE=""
PENDING_SSH_FILE="/var/lib/secure-linux-wizard/pending-ssh.conf"

OS_FAMILY=""
OS_ID=""
OS_VERSION=""
SSH_SERVICE=""
FIREWALL_KIND=""
PUBLIC_IFACE=""
CURRENT_SSH_PORT="22"
ADMIN_USER=""
ALLOW_USERS=""
SSH_PORT="22"
TRUSTED_CIDRS=""
INBOUND_TCP=""
INBOUND_UDP=""
HAS_DOCKER=0
HAS_FORWARDING=0
HAS_VPN=0
KEY_READY=0
ENABLE_FIREWALL=1
ENABLE_FAIL2BAN=1
ENABLE_UPDATES=1
ENABLE_JOURNAL=1
ENABLE_SYSCTL=1
ENABLE_AUDIT_TOOLS=1
ENABLE_PASSWORD_POLICY=1
ALLOW_SSH_TUNNELS=0
EXISTING_ALLOW_USERS=""

green=$'\033[32m'
yellow=$'\033[33m'
red=$'\033[31m'
blue=$'\033[36m'
bold=$'\033[1m'
reset=$'\033[0m'

t() {
    local key="$1"
    case "${LANGUAGE:-en}:$key" in
        ru:choose_language) printf 'Выберите язык / Choose language' ;;
        en:choose_language) printf 'Choose language / Выберите язык' ;;
        ru:choose_role) printf 'Что настроить?' ;;
        en:choose_role) printf 'What do you want to configure?' ;;
        ru:role_server) printf 'Server — защита Linux-сервера' ;;
        en:role_server) printf 'Server — harden a Linux server' ;;
        ru:role_admin) printf "Admin's PC — SSH-ключ и профиль на Linux/macOS/WSL" ;;
        en:role_admin) printf "Admin's PC — SSH key and profile on Linux/macOS/WSL" ;;
        ru:role_audit) printf 'Audit — только проверка сервера' ;;
        en:role_audit) printf 'Audit — inspect the server without configuration changes' ;;
        ru:invalid_choice) printf 'Введите один из предложенных номеров.' ;;
        en:invalid_choice) printf 'Enter one of the listed numbers.' ;;
        ru:yes_hint) printf 'Д/н' ;;
        en:yes_hint) printf 'Y/n' ;;
        ru:no_hint) printf 'д/Н' ;;
        en:no_hint) printf 'y/N' ;;
        ru:need_root) printf 'Серверный режим запустите через sudo: sudo bash %s' "$0" ;;
        en:need_root) printf 'Run server mode through sudo: sudo bash %s' "$0" ;;
        ru:log_at) printf 'Подробный журнал: %s' "$LOG_FILE" ;;
        en:log_at) printf 'Detailed log: %s' "$LOG_FILE" ;;
        ru:backup_at) printf 'Точка восстановления: %s' "$BACKUP_DIR" ;;
        en:backup_at) printf 'Recovery point: %s' "$BACKUP_DIR" ;;
        ru:dry_run) printf 'Режим проверки: изменения не выполняются.' ;;
        en:dry_run) printf 'Dry-run mode: no changes will be made.' ;;
        ru:preflight_title) printf 'Предварительная проверка' ;;
        en:preflight_title) printf 'Pre-flight review' ;;
        ru:snapshot_confirm) printf 'Есть snapshot/резервная копия и доступ к аварийной консоли провайдера?' ;;
        en:snapshot_confirm) printf 'Do you have a snapshot/backup and access to the provider recovery console?' ;;
        ru:abort_snapshot) printf 'Остановлено. Сначала создайте snapshot и проверьте аварийную консоль.' ;;
        en:abort_snapshot) printf 'Stopped. Create a snapshot and verify recovery-console access first.' ;;
        ru:admin_user) printf 'Имя администратора Linux' ;;
        en:admin_user) printf 'Linux administrator username' ;;
        ru:ssh_users) printf 'Пользователи, которым разрешён SSH (через запятую)' ;;
        en:ssh_users) printf 'Users allowed to use SSH (comma-separated)' ;;
        ru:ssh_port) printf 'Порт SSH' ;;
        en:ssh_port) printf 'SSH port' ;;
        ru:tcp_ports) printf 'Публичные TCP-порты, которые нужно оставить (через запятую; пусто = ни одного)' ;;
        en:tcp_ports) printf 'Public TCP ports to keep (comma-separated; empty = none)' ;;
        ru:udp_ports) printf 'Публичные UDP-порты, которые нужно оставить (через запятую; пусто = ни одного)' ;;
        en:udp_ports) printf 'Public UDP ports to keep (comma-separated; empty = none)' ;;
        ru:trusted_cidrs) printf 'Доверенные IP/CIDR для Fail2Ban (необязательно, через пробел)' ;;
        en:trusted_cidrs) printf 'Trusted IP/CIDR values for Fail2Ban (optional, space-separated)' ;;
        ru:key_menu) printf 'SSH-ключ администратора' ;;
        en:key_menu) printf 'Administrator SSH key' ;;
        ru:key_existing) printf 'Ключ уже есть в authorized_keys этого пользователя' ;;
        en:key_existing) printf "A key is already present in this user's authorized_keys" ;;
        ru:key_paste) printf 'Вставить открытый ключ сейчас' ;;
        en:key_paste) printf 'Paste a public key now' ;;
        ru:key_postpone) printf 'Пока пропустить (пароли и root-вход отключены не будут)' ;;
        en:key_postpone) printf 'Postpone (password and root login will remain unchanged)' ;;
        ru:paste_key) printf 'Вставьте одну строку открытого ключа (.pub), НЕ приватный ключ' ;;
        en:paste_key) printf 'Paste one public-key (.pub) line, NOT the private key' ;;
        ru:new_user_password) printf 'Для нового администратора задайте локальный пароль sudo. Ввод не отображается и не пишется в журнал.' ;;
        en:new_user_password) printf 'Set a local sudo password for the new administrator. Input is hidden and is not logged.' ;;
        ru:feature_firewall) printf 'Настроить межсетевой экран?' ;;
        en:feature_firewall) printf 'Configure the host firewall?' ;;
        ru:feature_f2b) printf 'Настроить Fail2Ban для SSH?' ;;
        en:feature_f2b) printf 'Configure Fail2Ban for SSH?' ;;
        ru:feature_updates) printf 'Включить автоматические security-обновления без автоперезагрузки?' ;;
        en:feature_updates) printf 'Enable automatic security updates without automatic reboot?' ;;
        ru:feature_journal) printf 'Включить постоянный системный журнал?' ;;
        en:feature_journal) printf 'Enable persistent system logs?' ;;
        ru:feature_sysctl) printf 'Применить совместимый базовый sysctl-профиль (без forwarding/rp_filter)?' ;;
        en:feature_sysctl) printf 'Apply the compatibility-safe sysctl baseline (without forwarding/rp_filter changes)?' ;;
        ru:feature_audit) printf 'Установить auditd и Lynis, если доступны?' ;;
        en:feature_audit) printf 'Install auditd and Lynis when available?' ;;
        ru:feature_passwords) printf 'Усилить правила для будущих локальных паролей?' ;;
        en:feature_passwords) printf 'Strengthen policy for future local passwords?' ;;
        ru:ssh_tunnels) printf 'Нужны SSH-туннели/port forwarding (например, -L/-R или VS Code Remote)?' ;;
        en:ssh_tunnels) printf 'Do you need SSH tunnels/port forwarding (for example -L/-R or VS Code Remote)?' ;;
        ru:confirm_plan) printf 'Применить показанный план?' ;;
        en:confirm_plan) printf 'Apply the displayed plan?' ;;
        ru:keep_session) printf 'НЕ закрывайте текущий SSH-сеанс до проверки второго входа.' ;;
        en:keep_session) printf 'DO NOT close the current SSH session until a second login succeeds.' ;;
        ru:test_second) printf 'Откройте ВТОРОЙ терминал и проверьте вход по ключу командой:' ;;
        en:test_second) printf 'Open a SECOND terminal and test key login with:' ;;
        ru:did_test) printf 'Новый вход по ключу и sudo успешно проверены в другом терминале?' ;;
        en:did_test) printf 'Did key login and sudo both succeed in another terminal?' ;;
        ru:lockdown_pending) printf 'Парольный/root-вход пока сохранён. После проверки выполните: sudo secure-linux-wizard --finalize-ssh' ;;
        en:lockdown_pending) printf 'Password/root login remains available. After testing run: sudo secure-linux-wizard --finalize-ssh' ;;
        ru:type_lockdown) printf 'Для отключения password/root-входа введите LOCKDOWN' ;;
        en:type_lockdown) printf 'Type LOCKDOWN to disable password/root login' ;;
        ru:lockdown_done) printf 'SSH переведён на вход только по ключу; root-вход отключён.' ;;
        en:lockdown_done) printf 'SSH now accepts key authentication only; root login is disabled.' ;;
        ru:unsupported_os) printf 'Поддерживаются Ubuntu/Debian и Fedora/RHEL-подобные системы с systemd.' ;;
        en:unsupported_os) printf 'Supported servers are Ubuntu/Debian and Fedora/RHEL-like systems with systemd.' ;;
        ru:complete) printf 'Готово. Сервер автоматически не перезагружался.' ;;
        en:complete) printf 'Complete. The server was not rebooted automatically.' ;;
        ru:reboot_needed) printf 'Система сообщает, что требуется плановая перезагрузка.' ;;
        en:reboot_needed) printf 'The system reports that a planned reboot is required.' ;;
        ru:client_alias) printf 'Короткое имя подключения (например, myvps)' ;;
        en:client_alias) printf 'Connection alias (for example, myvps)' ;;
        ru:server_host) printf 'IP-адрес или домен сервера' ;;
        en:server_host) printf 'Server IP address or hostname' ;;
        ru:server_user) printf 'SSH-пользователь сервера' ;;
        en:server_user) printf 'Server SSH username' ;;
        ru:key_path) printf 'Путь нового/существующего приватного ключа' ;;
        en:key_path) printf 'Path to the new/existing private key' ;;
        ru:generate_key) printf 'Создать новый Ed25519-ключ?' ;;
        en:generate_key) printf 'Generate a new Ed25519 key?' ;;
        ru:copy_key) printf 'Скопировать открытый ключ на сервер сейчас (потребуется текущий пароль сервера)?' ;;
        en:copy_key) printf 'Copy the public key to the server now (the current server password may be required)?' ;;
        ru:agent_note) printf 'Кодовая фраза не сохраняется в файле. ssh-agent запоминает её на время сеанса; на macOS используется Keychain.' ;;
        en:agent_note) printf 'The passphrase is never stored in a file. ssh-agent caches it for the session; macOS uses Keychain.' ;;
        ru:client_done) printf 'ПК администратора настроен. Подключение: ssh %s' "$2" ;;
        en:client_done) printf "Administrator's PC is configured. Connect with: ssh %s" "$2" ;;
        ru:audit_title) printf 'АУДИТ LINUX-СЕРВЕРА' ;;
        en:audit_title) printf 'LINUX SERVER AUDIT' ;;
        ru:rollback_confirm) printf 'Восстановить конфигурационные файлы из %s?' "$2" ;;
        en:rollback_confirm) printf 'Restore configuration files from %s?' "$2" ;;
        ru:rollback_done) printf 'Файлы восстановлены. Проверьте SSH, firewall и службы до закрытия сессии.' ;;
        en:rollback_done) printf 'Files restored. Verify SSH, firewall, and services before closing this session.' ;;
        *) printf '%s' "$key" ;;
    esac
}

ts() { date -u +'%Y-%m-%dT%H:%M:%SZ'; }
info() { printf '%s%s[INFO]%s %s\n' "$(ts) " "$blue" "$reset" "$*"; }
ok()   { printf '%s%s[ OK ]%s %s\n' "$(ts) " "$green" "$reset" "$*"; }
warn() {
    printf '%s%s[WARN]%s %s\n' "$(ts) " "$yellow" "$reset" "$*" >&2
    if [[ -n "${WARNINGS_FILE:-}" ]]; then printf '%s\n' "$*" >> "$WARNINGS_FILE"; fi
}
err()  { printf '%s%s[ERR ]%s %s\n' "$(ts) " "$red" "$reset" "$*" >&2; }
die()  { err "$*"; exit 1; }

usage() {
    cat <<'EOF'
Secure Linux Wizard / Мастер защиты Linux

Interactive / Интерактивно:
  bash secure-linux-wizard.sh

Server / Сервер:
  sudo bash secure-linux-wizard.sh --role server [--lang ru|en] [--dry-run]
  sudo secure-linux-wizard --audit [--lang ru|en]
  sudo secure-linux-wizard --finalize-ssh [--lang ru|en]
  sudo secure-linux-wizard --rollback BACKUP_DIR [--lang ru|en]

Admin's PC (Linux/macOS/WSL):
  bash secure-linux-wizard.sh --role admin [--lang ru|en]

Options / Параметры:
  --lang ru|en            interface language / язык интерфейса
  --role server|admin     target role / режим
  --audit                 server audit only / только аудит
  --dry-run               show planned changes / показать план
  --finalize-ssh          disable SSH passwords/root after key test
  --rollback DIR          restore files from a recovery point
  --admin-user USER       value for finalize automation
  --ssh-port PORT         value for finalize automation
  --allow-users "A B"     value for finalize automation
  --yes                   accept safe defaults; never auto-finalizes SSH
  --snapshot-confirmed    confirm an external snapshot/recovery console
  -h, --help              this help / эта справка
EOF
}

while (($#)); do
    case "$1" in
        --lang) [[ $# -ge 2 ]] || die '--lang requires ru or en'; LANGUAGE="$2"; shift ;;
        --role) [[ $# -ge 2 ]] || die '--role requires server or admin'; ROLE="$2"; shift ;;
        --audit) ACTION="audit"; ROLE="server" ;;
        --dry-run) DRY_RUN=1 ;;
        --finalize-ssh) ACTION="finalize"; ROLE="server" ;;
        --rollback) [[ $# -ge 2 ]] || die '--rollback requires a directory'; ACTION="rollback"; ROLE="server"; ROLLBACK_DIR="$2"; shift ;;
        --admin-user) [[ $# -ge 2 ]] || die '--admin-user requires a value'; CLI_ADMIN_USER="$2"; shift ;;
        --ssh-port) [[ $# -ge 2 ]] || die '--ssh-port requires a value'; CLI_SSH_PORT="$2"; shift ;;
        --allow-users) [[ $# -ge 2 ]] || die '--allow-users requires a value'; CLI_ALLOW_USERS="$2"; shift ;;
        --yes) ASSUME_YES=1 ;;
        --snapshot-confirmed) SNAPSHOT_CONFIRMED=1 ;;
        -h|--help) usage; exit 0 ;;
        *) die "Unknown option / Неизвестный параметр: $1" ;;
    esac
    shift
done

[[ -z "$LANGUAGE" || "$LANGUAGE" == "ru" || "$LANGUAGE" == "en" ]] \
    || die "Invalid language / Недопустимый язык: $LANGUAGE"
[[ -z "$ROLE" || "$ROLE" == "server" || "$ROLE" == "admin" ]] \
    || die "Invalid role / Недопустимый режим: $ROLE"

choose_language() {
    [[ "$LANGUAGE" == "ru" || "$LANGUAGE" == "en" ]] && return 0
    printf '\n%s\n  1) Русский\n  2) English\n> ' "$(t choose_language)"
    local answer
    read -r answer
    case "$answer" in 1|ru|RU) LANGUAGE="ru" ;; 2|en|EN|'') LANGUAGE="en" ;; *) LANGUAGE="en" ;; esac
}

choose_role() {
    [[ "$ROLE" == "server" || "$ROLE" == "admin" ]] && return 0
    printf '\n%s\n  1) %s\n  2) %s\n  3) %s\n> ' \
        "$(t choose_role)" "$(t role_server)" "$(t role_admin)" "$(t role_audit)"
    local answer
    read -r answer
    case "$answer" in
        1|server|Server) ROLE="server" ;;
        2|admin|Admin) ROLE="admin" ;;
        3|audit|Audit) ROLE="server"; ACTION="audit" ;;
        *) die "$(t invalid_choice)" ;;
    esac
}

ask() {
    local prompt="$1" default="${2:-}" answer
    if ((ASSUME_YES)); then printf '%s' "$default"; return 0; fi
    if [[ -n "$default" ]]; then printf '%s [%s]: ' "$prompt" "$default" >&2; else printf '%s: ' "$prompt" >&2; fi
    read -r answer
    printf '%s' "${answer:-$default}"
}

confirm() {
    local prompt="$1" default="${2:-no}" answer hint
    if ((ASSUME_YES)); then [[ "$default" == "yes" ]]; return; fi
    if [[ "$default" == "yes" ]]; then hint="$(t yes_hint)"; else hint="$(t no_hint)"; fi
    while true; do
        printf '%s [%s]: ' "$prompt" "$hint" >&2
        read -r answer
        answer="${answer:-$default}"
        case "${answer,,}" in
            y|yes|д|да) return 0 ;;
            n|no|н|нет) return 1 ;;
            *) printf '%s\n' "$(t invalid_choice)" >&2 ;;
        esac
    done
}

validate_user() { [[ "$1" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; }
validate_port() { [[ "$1" =~ ^[0-9]+$ ]] && ((10#$1 >= 1 && 10#$1 <= 65535)); }

normalize_csv_ports() {
    local raw="${1// /}" item out="" old_ifs="$IFS"
    [[ -z "$raw" ]] && return 0
    IFS=','
    for item in $raw; do
        validate_port "$item" || die "Invalid port / Недопустимый порт: $item"
        case ",$out," in *",$item,"*) ;; *) out="${out:+$out,}$item" ;; esac
    done
    IFS="$old_ifs"
    printf '%s' "$out"
}

csv_to_spaces() { printf '%s' "${1//,/ }" | xargs; }

validate_user_list() {
    local list item
    list="$(csv_to_spaces "$1")"
    [[ -n "$list" ]] || die "At least one SSH user is required / Нужен хотя бы один SSH-пользователь"
    while IFS= read -r item; do
        [[ -n "$item" ]] || continue
        validate_user "$item" || die "Invalid user / Недопустимый пользователь: $item"
    done < <(tr ' ' '\n' <<< "$list")
    printf '%s' "$list"
}

init_log() {
    local log_dir
    if ((DRY_RUN)) || [[ "$ACTION" == "audit" ]]; then
        log_dir="${TMPDIR:-/tmp}/secure-linux-wizard-logs"
        install -d -m 700 "$log_dir"
    elif [[ "$ROLE" == "server" ]]; then
        log_dir="/var/log/secure-linux-wizard"
        install -d -o root -g root -m 700 "$log_dir"
    else
        log_dir="${XDG_STATE_HOME:-$HOME/.local/state}/secure-linux-wizard"
        mkdir -p "$log_dir"
        chmod 700 "$log_dir"
    fi
    LOG_FILE="$log_dir/${ACTION}-${RUN_ID}.log"
    : > "$LOG_FILE"
    chmod 600 "$LOG_FILE"
    exec > >(tee -a "$LOG_FILE") 2>&1
    info "Secure Linux Wizard ${SCRIPT_VERSION}"
    info "$(t log_at)"
    if ((DRY_RUN)); then warn "$(t dry_run)"; fi
    return 0
}

command_exists() { command -v "$1" >/dev/null 2>&1; }

unit_exists() {
    local unit="$1"
    systemctl list-unit-files --type=service --no-legend "$unit" 2>/dev/null \
        | awk '{print $1}' | grep -Fxq "$unit"
}

quote_command() {
    local q item
    for item in "$@"; do printf -v q '%q' "$item"; printf '%s ' "$q"; done
}

run() {
    info "RUN: $(quote_command "$@")"
    ((DRY_RUN)) && return 0
    "$@"
}

run_optional() {
    info "RUN: $(quote_command "$@")"
    ((DRY_RUN)) && return 0
    if ! "$@"; then warn "Optional command failed / Необязательная команда завершилась ошибкой: $(quote_command "$@")"; return 1; fi
}

on_error() {
    local rc=$?
    err "Unexpected failure / Непредвиденная ошибка: rc=${rc}, line=${BASH_LINENO[0]}"
    [[ -n "${BACKUP_DIR:-}" ]] && err "$(t backup_at)"
    exit "$rc"
}
trap on_error ERR

safe_managed_path() {
    local p="$1"
    [[ "$p" == /* ]] || return 1
    [[ "$p" != *$'\n'* && "$p" != *$'\r'* && "$p" != *'//'*
        && "$p" != */. && "$p" != *'/./'*
        && "$p" != */.. && "$p" != *'/../'* ]] || return 1
    case "$p" in
        /etc/?*|/usr/local/sbin/?*|/var/lib/secure-linux-wizard/?*|/home/*/.ssh|/home/*/.ssh/?*|/root/.ssh|/root/.ssh/?*) return 0 ;;
        *) return 1 ;;
    esac
}

validate_admin_ssh_paths() {
    local user="$1" home="$2" ssh_dir auth expected_uid actual_uid
    ssh_dir="$home/.ssh"
    auth="$ssh_dir/authorized_keys"
    [[ "$home" == "/home/$user" ]] \
        || die "Administrator home must be /home/$user / Дом администратора должен быть /home/$user"
    [[ -d "$home" && ! -L "$home" ]] \
        || die "Administrator home is missing or is a symlink / Дом администратора отсутствует или является ссылкой: $home"
    expected_uid="$(id -u "$user")"
    actual_uid="$(stat -c '%u' "$home")"
    [[ "$actual_uid" == "$expected_uid" ]] \
        || die "Administrator home has an unexpected owner / Неверный владелец домашнего каталога: $home"
    find "$home" -maxdepth 0 -perm /022 -print -quit | grep -q . \
        && die "Administrator home must not be group/world-writable / Дом администратора не должен быть доступен для записи группе/всем: $home"
    if [[ -e "$ssh_dir" || -L "$ssh_dir" ]]; then
        [[ -d "$ssh_dir" && ! -L "$ssh_dir" ]] \
            || die ".ssh must be a real directory, not a symlink / .ssh должен быть обычным каталогом: $ssh_dir"
    fi
    if [[ -e "$auth" || -L "$auth" ]]; then
        [[ -f "$auth" && ! -L "$auth" ]] \
            || die "authorized_keys must be a regular file / authorized_keys должен быть обычным файлом: $auth"
    fi
}

backup_path() {
    local path="$1" key
    [[ "$ACTION" == "wizard" || "$ACTION" == "finalize" ]] || return 0
    ((DRY_RUN)) && return 0
    safe_managed_path "$path" || die "Refusing unexpected backup path / Отказ резервировать неожиданный путь: $path"
    grep -Fxq -- "$path" "$MANIFEST" 2>/dev/null && return 0
    key="${path#/}"
    mkdir -p "$FILES_DIR/$(dirname "$key")" "$ABSENT_DIR/$(dirname "$key")"
    if [[ -e "$path" || -L "$path" ]]; then
        cp -a -- "$path" "$FILES_DIR/$key"
    else
        : > "$ABSENT_DIR/$key"
    fi
    printf '%s\n' "$path" >> "$MANIFEST"
}

restore_path_from_current_backup() {
    local path="$1" key src absent
    ((DRY_RUN)) && return 0
    [[ -n "${BACKUP_DIR:-}" ]] || return 1
    safe_managed_path "$path" || return 1
    key="${path#/}"
    src="$FILES_DIR/$key"
    absent="$ABSENT_DIR/$key"
    if [[ -e "$src" || -L "$src" ]]; then
        rm -rf --one-file-system -- "$path"
        mkdir -p "$(dirname "$path")"
        cp -a -- "$src" "$path"
        return 0
    fi
    if [[ -e "$absent" ]]; then
        rm -rf --one-file-system -- "$path"
        return 0
    fi
    return 1
}

put_file() {
    local path="$1" mode="$2" owner="$3" group="$4" tmp
    tmp="$(mktemp)"
    cat > "$tmp"
    if ((DRY_RUN)); then
        info "Would write / Будет записан файл: $path"
        rm -f "$tmp"
        return 0
    fi
    backup_path "$path"
    install -D --remove-destination -m "$mode" -o "$owner" -g "$group" "$tmp" "$path"
    rm -f "$tmp"
}

prepare_backup() {
    ((DRY_RUN)) && { BACKUP_DIR="/root/secure-linux-wizard-backups/DRY-RUN-${STAMP}"; return 0; }
    BACKUP_DIR="/root/secure-linux-wizard-backups/${STAMP}"
    FILES_DIR="$BACKUP_DIR/files"
    ABSENT_DIR="$BACKUP_DIR/absent"
    MANIFEST="$BACKUP_DIR/manifest.txt"
    WARNINGS_FILE="$BACKUP_DIR/warnings.txt"
    install -d -o root -g root -m 700 "$FILES_DIR" "$ABSENT_DIR"
    : > "$MANIFEST"; : > "$WARNINGS_FILE"
    chmod 600 "$MANIFEST" "$WARNINGS_FILE"
    cp -a -- "$0" "$BACKUP_DIR/secure-linux-wizard.sh" 2>/dev/null || true
    chmod 700 "$BACKUP_DIR/secure-linux-wizard.sh" 2>/dev/null || true
    {
        printf 'version=%s\n' "$SCRIPT_VERSION"
        printf 'created_utc=%s\n' "$(ts)"
        printf 'host=%s\n' "$(hostname -f 2>/dev/null || hostname)"
        printf 'action=%s\n' "$ACTION"
    } > "$BACKUP_DIR/run-info.txt"
    ok "$(t backup_at)"
}

rollback_files() {
    local base="$1" path key src absent
    [[ ${EUID:-$(id -u)} -eq 0 ]] || die "$(t need_root)"
    [[ ! -L "$base" ]] || die "Recovery point must not be a symlink / Точка восстановления не должна быть ссылкой"
    [[ -d "$base/files" && -f "$base/manifest.txt" ]] || die "Invalid recovery point / Неверная точка восстановления: $base"
    [[ "$(stat -c '%u' "$base" 2>/dev/null || printf 1)" == "0" ]] \
        || die "Recovery point must be owned by root / Точка восстановления должна принадлежать root"
    find "$base" -maxdepth 0 -perm /022 -print -quit | grep -q . \
        && die "Recovery point must not be group/world-writable / Точка восстановления не должна быть доступна для записи группе/всем"
    if ((DRY_RUN)); then
        while IFS= read -r path; do
            [[ -n "$path" ]] || continue
            safe_managed_path "$path" || die "Unsafe manifest path / Небезопасный путь в manifest: $path"
            key="${path#/}"; src="$base/files/$key"; absent="$base/absent/$key"
            if [[ -e "$src" || -L "$src" ]]; then
                info "Would restore / Будет восстановлено: $path"
            elif [[ -e "$absent" ]]; then
                info "Would remove newly created path / Будет удалён новый путь: $path"
            fi
        done < "$base/manifest.txt"
        return 0
    fi
    confirm "$(t rollback_confirm "$base")" no || exit 0
    while IFS= read -r path; do
        [[ -n "$path" ]] || continue
        safe_managed_path "$path" || die "Unsafe manifest path / Небезопасный путь в manifest: $path"
        key="${path#/}"; src="$base/files/$key"; absent="$base/absent/$key"
        if [[ -e "$src" || -L "$src" ]]; then
            if [[ -e "$path" || -L "$path" ]]; then rm -rf --one-file-system -- "$path"; fi
            mkdir -p "$(dirname "$path")"
            cp -a -- "$src" "$path"
            info "Restored / Восстановлено: $path"
        elif [[ -e "$absent" ]]; then
            if [[ -e "$path" || -L "$path" ]]; then rm -rf --one-file-system -- "$path"; fi
            info "Removed newly created path / Удалён новый путь: $path"
        fi
    done < "$base/manifest.txt"
    systemctl daemon-reload 2>/dev/null || true
    if command_exists sshd; then
        sshd -t 2>/dev/null || warn "sshd validation needs attention / Требуется проверить sshd"
    fi
    if command_exists ufw; then ufw reload >/dev/null 2>&1 || true; fi
    systemctl reload firewalld >/dev/null 2>&1 || true
    systemctl reload ssh >/dev/null 2>&1 || systemctl reload sshd >/dev/null 2>&1 || true
    sysctl --system >/dev/null 2>&1 || true
    ok "$(t rollback_done)"
}

detect_server() {
    local ssh_effective=""
    [[ -r /etc/os-release ]] || die "$(t unsupported_os)"
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_VERSION="${VERSION_ID:-unknown}"
    case "${ID_LIKE:-} ${ID:-}" in
        *debian*|*ubuntu*) OS_FAMILY="debian"; FIREWALL_KIND="ufw" ;;
        *fedora*|*rhel*|*centos*) OS_FAMILY="rhel"; FIREWALL_KIND="firewalld" ;;
        *) die "$(t unsupported_os)" ;;
    esac
    command_exists systemctl || die "systemd is required / Требуется systemd"
    if unit_exists ssh.service; then
        SSH_SERVICE="ssh"
    else
        SSH_SERVICE="sshd"
    fi
    if command_exists sshd; then ssh_effective="$(sshd -T 2>/dev/null || true)"; fi
    CURRENT_SSH_PORT="$(awk '$1=="port" {print $2; exit}' <<< "$ssh_effective")"
    CURRENT_SSH_PORT="${CURRENT_SSH_PORT:-22}"
    EXISTING_ALLOW_USERS="$(awk '$1=="allowusers" {$1=""; sub(/^[[:space:]]+/,""); print; exit}' <<< "$ssh_effective")"
    PUBLIC_IFACE="$( { ip -4 route show default 2>/dev/null || true; } | awk 'NR==1 {for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}')"
    HAS_DOCKER=0; systemctl is-active --quiet docker >/dev/null 2>&1 && HAS_DOCKER=1
    HAS_FORWARDING=0
    [[ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null || printf 0)" == "1" ]] && HAS_FORWARDING=1
    [[ "$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null || printf 0)" == "1" ]] && HAS_FORWARDING=1
    HAS_VPN=0
    if ip -brief link 2>/dev/null | grep -Eqi '(^| )(wg|tun|tap|amn|tailscale|zt)'; then HAS_VPN=1; fi
    if systemctl list-units --type=service --all --no-legend 2>/dev/null | grep -Eqi 'wireguard|openvpn|tailscale|zerotier|amnezia'; then HAS_VPN=1; fi
}

public_listeners() {
    local proto="$1"
    ss -H -ln"${proto}" 2>/dev/null | awk '{a=$4; sub(/^.*:/,"",a); if ($4 ~ /^(0\.0\.0\.0:|\[::\]:|\*:)/ && a ~ /^[0-9]+$/) print a}' | sort -n -u | paste -sd, -
}

install_self() {
    ((DRY_RUN)) && { info 'Would install /usr/local/sbin/secure-linux-wizard'; return; }
    backup_path /usr/local/sbin/secure-linux-wizard
    install --remove-destination -m 750 -o root -g root "$0" /usr/local/sbin/secure-linux-wizard
}

install_required_packages() {
    info "Installing required packages / Установка необходимых пакетов"
    if [[ "$OS_FAMILY" == "debian" ]]; then
        run apt-get update
        local packages=(openssh-server ca-certificates)
        ((ENABLE_FIREWALL)) && packages+=(ufw)
        ((ENABLE_FAIL2BAN)) && packages+=(fail2ban)
        ((ENABLE_UPDATES)) && packages+=(unattended-upgrades)
        ((ENABLE_AUDIT_TOOLS)) && packages+=(auditd)
        ((ENABLE_PASSWORD_POLICY)) && packages+=(libpam-pwquality)
        run env DEBIAN_FRONTEND=noninteractive apt-get install -y "${packages[@]}"
        # Lynis is optional and is not present in every configured mirror.
        if ((ENABLE_AUDIT_TOOLS)); then run_optional env DEBIAN_FRONTEND=noninteractive apt-get install -y lynis || true; fi
    else
        local packages=(openssh-server policycoreutils)
        ((ENABLE_FIREWALL)) && packages+=(firewalld)
        ((ENABLE_AUDIT_TOOLS)) && packages+=(audit)
        run dnf -y install "${packages[@]}"
        if ((ENABLE_FAIL2BAN)); then run_optional dnf -y install fail2ban || true; fi
        if ((ENABLE_UPDATES)); then run_optional dnf -y install dnf-automatic || true; fi
        if ((ENABLE_PASSWORD_POLICY)); then run_optional dnf -y install libpwquality || true; fi
        if ((ENABLE_AUDIT_TOOLS)); then run_optional dnf -y install lynis || true; fi
    fi
    if ((ENABLE_FAIL2BAN)) && ((DRY_RUN==0)) && ! command_exists fail2ban-client; then
        warn "Fail2Ban is unavailable; its configuration is skipped / Fail2Ban недоступен; настройка пропущена"
        ENABLE_FAIL2BAN=0
    fi
}

ensure_admin_user() {
    local created=0 group home primary_group
    if id "$ADMIN_USER" >/dev/null 2>&1; then
        info "Using existing administrator / Используется существующий администратор: $ADMIN_USER"
    else
        run useradd --create-home --shell /bin/bash "$ADMIN_USER"
        created=1
    fi
    if getent group sudo >/dev/null 2>&1; then group="sudo"; else group="wheel"; fi
    if id "$ADMIN_USER" >/dev/null 2>&1; then
        id -nG "$ADMIN_USER" | tr ' ' '\n' | grep -Fxq "$group" || run usermod -aG "$group" "$ADMIN_USER"
        home="$(getent passwd "$ADMIN_USER" | cut -d: -f6)"
        primary_group="$(id -gn "$ADMIN_USER")"
        validate_admin_ssh_paths "$ADMIN_USER" "$home"
    else
        # In --dry-run mode useradd is deliberately not executed.
        home="/home/$ADMIN_USER"
        primary_group="$ADMIN_USER"
        run usermod -aG "$group" "$ADMIN_USER"
    fi
    if ((created)) && ((DRY_RUN==0)); then
        printf '\n%s\n' "$(t new_user_password)"
        passwd "$ADMIN_USER"
    fi
    if ((DRY_RUN)); then
        info "Would prepare / Будет подготовлен: $home/.ssh"
    else
        backup_path "$home/.ssh"
        install -d -m 700 -o "$ADMIN_USER" -g "$primary_group" "$home/.ssh"
        touch "$home/.ssh/authorized_keys"
        chown "$ADMIN_USER:$primary_group" "$home/.ssh/authorized_keys"
        chmod 600 "$home/.ssh/authorized_keys"
    fi
}

provision_admin_key() {
    local home auth key_choice key_line tmp primary_group existing_mark=""
    home="$( { getent passwd "$ADMIN_USER" 2>/dev/null || true; } | cut -d: -f6)"
    home="${home:-/home/$ADMIN_USER}"
    auth="$home/.ssh/authorized_keys"
    if id "$ADMIN_USER" >/dev/null 2>&1; then
        validate_admin_ssh_paths "$ADMIN_USER" "$home"
    fi
    if [[ -s "$auth" ]]; then KEY_READY=1; fi
    if ((ASSUME_YES)); then return 0; fi
    [[ -s "$auth" ]] && existing_mark=' [OK]'
    printf '\n%s\n  1) %s%s\n  2) %s\n  3) %s\n> ' \
        "$(t key_menu)" "$(t key_existing)" "$existing_mark" "$(t key_paste)" "$(t key_postpone)"
    read -r key_choice
    case "$key_choice" in
        1)
            [[ -s "$auth" ]] || die "authorized_keys is empty / authorized_keys пуст"
            KEY_READY=1
            ;;
        2)
            printf '%s: ' "$(t paste_key)" >&2
            read -r key_line
            [[ "$key_line" == ssh-*' '* || "$key_line" == ecdsa-*' '* || "$key_line" == sk-*' '* ]] \
                || die "Invalid public key format / Неверный формат открытого ключа"
            tmp="$(mktemp)"; printf '%s\n' "$key_line" > "$tmp"
            ssh-keygen -lf "$tmp" >/dev/null || { rm -f "$tmp"; die "ssh-keygen rejected the public key / ssh-keygen отклонил ключ"; }
            rm -f "$tmp"
            if ((DRY_RUN)); then
                info "Would append validated public key / Проверенный ключ будет добавлен: $auth"
            else
                backup_path "$auth"
                grep -qxF -- "$key_line" "$auth" || printf '%s\n' "$key_line" >> "$auth"
                primary_group="$(id -gn "$ADMIN_USER")"
                chown "$ADMIN_USER:$primary_group" "$auth"; chmod 600 "$auth"
            fi
            KEY_READY=1
            ;;
        3|'') KEY_READY=0 ;;
        *) die "$(t invalid_choice)" ;;
    esac
}

ensure_sshd_include_first() {
    local config="/etc/ssh/sshd_config" tmp
    if head -n 5 "$config" 2>/dev/null | grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf([[:space:]]|$)'; then
        ((DRY_RUN)) || install -d -o root -g root -m 755 /etc/ssh/sshd_config.d
        return 0
    fi
    ((DRY_RUN)) && { info "Would prepend Include to $config"; return 0; }
    install -d -o root -g root -m 755 /etc/ssh/sshd_config.d
    backup_path "$config"
    tmp="$(mktemp)"
    {
        printf '%s\n' 'Include /etc/ssh/sshd_config.d/*.conf'
        cat "$config"
    } > "$tmp"
    install --remove-destination -m 600 -o root -g root "$tmp" "$config"
    rm -f "$tmp"
}

write_ssh_config() {
    local final="${1:-0}" tunnel_value="no"
    ((ALLOW_SSH_TUNNELS)) && tunnel_value="yes"
    ensure_sshd_include_first
    {
        cat <<EOF
# Managed by Secure Linux Wizard ${SCRIPT_VERSION}.
# Recovery copy: ${BACKUP_DIR:-see /root/secure-linux-wizard-backups}
Port ${SSH_PORT}
PubkeyAuthentication yes
PermitEmptyPasswords no
LoginGraceTime 30
MaxAuthTries 3
MaxSessions 10
LogLevel VERBOSE
IgnoreRhosts yes
HostbasedAuthentication no
PermitUserEnvironment no
X11Forwarding no
AllowAgentForwarding no
GatewayPorts no
AllowTcpForwarding ${tunnel_value}
AllowStreamLocalForwarding ${tunnel_value}
PermitTunnel ${tunnel_value}
ClientAliveInterval 300
ClientAliveCountMax 2
EOF
        if ((final)); then
            cat <<EOF
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
AllowUsers ${ALLOW_USERS}
EOF
        elif [[ -n "$EXISTING_ALLOW_USERS" ]]; then
            printf 'AllowUsers %s %s\n' "$ALLOW_USERS" "$EXISTING_ALLOW_USERS"
        fi
    } | put_file /etc/ssh/sshd_config.d/00-secure-linux-wizard.conf 600 root root
    if ((DRY_RUN)); then return 0; fi
    if ! sshd -t; then
        restore_path_from_current_backup /etc/ssh/sshd_config.d/00-secure-linux-wizard.conf || true
        sshd -t 2>/dev/null || true
        die "Invalid SSH configuration was restored automatically / Неверная конфигурация SSH автоматически отменена"
    fi
    run systemctl reload "$SSH_SERVICE"
    ok "OpenSSH configuration validated / Конфигурация OpenSSH проверена"
}

write_pending_ssh_state() {
    if ((DRY_RUN)); then return 0; fi
    install -d -o root -g root -m 700 /var/lib/secure-linux-wizard
    backup_path "$PENDING_SSH_FILE"
    {
        printf 'ADMIN_USER=%s\n' "$ADMIN_USER"
        printf 'SSH_PORT=%s\n' "$SSH_PORT"
        printf 'ALLOW_USERS=%s\n' "$ALLOW_USERS"
        printf 'ALLOW_SSH_TUNNELS=%s\n' "$ALLOW_SSH_TUNNELS"
    } | put_file "$PENDING_SSH_FILE" 600 root root
}

read_pending_ssh_state() {
    local key value
    if [[ -f "$PENDING_SSH_FILE" ]]; then
        while IFS='=' read -r key value; do
            case "$key" in
                ADMIN_USER) ADMIN_USER="$value" ;;
                SSH_PORT) SSH_PORT="$value" ;;
                ALLOW_USERS) ALLOW_USERS="$value" ;;
                ALLOW_SSH_TUNNELS) ALLOW_SSH_TUNNELS="$value" ;;
            esac
        done < "$PENDING_SSH_FILE"
    fi
    ADMIN_USER="${CLI_ADMIN_USER:-$ADMIN_USER}"
    SSH_PORT="${CLI_SSH_PORT:-$SSH_PORT}"
    ALLOW_USERS="${CLI_ALLOW_USERS:-$ALLOW_USERS}"
    [[ -n "$ADMIN_USER" && -n "$SSH_PORT" && -n "$ALLOW_USERS" ]] \
        || die "No pending SSH state / Нет сохранённых параметров SSH. Run the main wizard first."
    validate_user "$ADMIN_USER" || die "Invalid administrator / Недопустимый администратор"
    [[ "$ADMIN_USER" != "root" ]] || die "The administrator must not be root / Администратор не должен быть root"
    validate_port "$SSH_PORT" || die "Invalid SSH port / Недопустимый порт SSH"
    ALLOW_USERS="$(validate_user_list "$ALLOW_USERS")"
    [[ "$ALLOW_SSH_TUNNELS" == "0" || "$ALLOW_SSH_TUNNELS" == "1" ]] || ALLOW_SSH_TUNNELS=0
}

finalize_ssh() {
    local home auth answer
    detect_server
    prepare_backup
    read_pending_ssh_state
    id "$ADMIN_USER" >/dev/null 2>&1 || die "Administrator does not exist / Администратор не существует: $ADMIN_USER"
    home="$(getent passwd "$ADMIN_USER" | cut -d: -f6)"; auth="$home/.ssh/authorized_keys"
    validate_admin_ssh_paths "$ADMIN_USER" "$home"
    [[ -s "$auth" ]] || die "No authorized key for $ADMIN_USER / Нет authorized_keys для $ADMIN_USER"
    if ((ASSUME_YES==0)); then
        printf '%s: ' "$(t type_lockdown)" >&2
        read -r answer
        [[ "$answer" == "LOCKDOWN" ]] || die "Cancelled / Отменено"
    fi
    write_ssh_config 1
    local effective
    effective="$(sshd -T 2>/dev/null)"
    grep -q '^permitrootlogin no$' <<< "$effective" || die "PermitRootLogin is not no"
    grep -q '^passwordauthentication no$' <<< "$effective" || die "PasswordAuthentication is not no"
    grep -q '^kbdinteractiveauthentication no$' <<< "$effective" || die "KbdInteractiveAuthentication is not no"
    if ((DRY_RUN==0)); then rm -f "$PENDING_SSH_FILE"; fi
    ok "$(t lockdown_done)"
    warn "$(t keep_session)"
}

configure_firewall() {
    ((ENABLE_FIREWALL)) || return 0
    local p
    local -a _tcp=() _udp=()
    if [[ "$FIREWALL_KIND" == "ufw" ]]; then
        backup_path /etc/ufw
        run ufw default deny incoming
        run ufw default allow outgoing
        run ufw limit in "${SSH_PORT}/tcp" comment 'SSH managed by Secure Linux Wizard'
        IFS=',' read -r -a _tcp <<< "$INBOUND_TCP"
        for p in "${_tcp[@]:-}"; do [[ -n "$p" && "$p" != "$SSH_PORT" ]] && run ufw allow in "${p}/tcp" comment 'allowed by Secure Linux Wizard'; done
        IFS=',' read -r -a _udp <<< "$INBOUND_UDP"
        for p in "${_udp[@]:-}"; do [[ -n "$p" ]] && run ufw allow in "${p}/udp" comment 'allowed by Secure Linux Wizard'; done
        if ((HAS_FORWARDING==0 && HAS_DOCKER==0 && HAS_VPN==0)); then run ufw default deny routed; else warn "Routed policy preserved because Docker/VPN/forwarding is active / Политика routed сохранена из-за Docker/VPN/forwarding"; fi
        run ufw --force enable
        run ufw reload
    else
        backup_path /etc/firewalld
        run systemctl enable --now firewalld
        run firewall-cmd --permanent --add-port="${SSH_PORT}/tcp"
        IFS=',' read -r -a _tcp <<< "$INBOUND_TCP"
        for p in "${_tcp[@]:-}"; do [[ -n "$p" ]] && run firewall-cmd --permanent --add-port="${p}/tcp"; done
        IFS=',' read -r -a _udp <<< "$INBOUND_UDP"
        for p in "${_udp[@]:-}"; do [[ -n "$p" ]] && run firewall-cmd --permanent --add-port="${p}/udp"; done
        run firewall-cmd --reload
        warn "Existing firewalld allowances were preserved. Review them in the audit / Существующие разрешения firewalld сохранены; проверьте их в аудите"
    fi
    if ((HAS_DOCKER)); then
        warn "Docker can bypass host-firewall rules for published ports. The wizard does not rewrite Docker networking automatically / Docker может обходить правила host firewall; мастер не переписывает сеть Docker автоматически"
    fi
}

configure_fail2ban() {
    ((ENABLE_FAIL2BAN)) || return 0
    local banaction="" ignore="127.0.0.1/8 ::1"
    local jail_path="/etc/fail2ban/jail.d/90-secure-linux-wizard.local"
    [[ -n "$TRUSTED_CIDRS" ]] && ignore="$ignore $TRUSTED_CIDRS"
    [[ -f /etc/fail2ban/action.d/ufw.conf && "$FIREWALL_KIND" == "ufw" ]] && banaction='banaction = ufw'
    {
        cat <<EOF
# Managed by Secure Linux Wizard ${SCRIPT_VERSION}
[sshd]
enabled = true
backend = systemd
port = ${SSH_PORT}
filter = sshd
ignoreip = ${ignore}
maxretry = 5
findtime = 600
bantime = 3600
bantime.increment = true
bantime.maxtime = 604800
${banaction}
EOF
    } | put_file "$jail_path" 640 root root
    ((DRY_RUN)) && return 0
    if ! fail2ban-client -t; then
        restore_path_from_current_backup "$jail_path" || true
        fail2ban-client -t >/dev/null 2>&1 || true
        die "Fail2Ban rejected the generated jail; it was restored automatically / Fail2Ban отклонил jail; файл автоматически восстановлен"
    fi
    run systemctl enable fail2ban
    if ! run systemctl restart fail2ban; then
        restore_path_from_current_backup "$jail_path" || true
        systemctl restart fail2ban >/dev/null 2>&1 || true
        die "Fail2Ban could not restart; its previous jail was restored / Fail2Ban не перезапустился; предыдущий jail восстановлен"
    fi
    local _attempt
    for _attempt in {1..15}; do
        fail2ban-client ping >/dev/null 2>&1 && break
        sleep 1
    done
    fail2ban-client ping >/dev/null
    fail2ban-client status sshd >/dev/null
    ok "Fail2Ban SSH jail is active / SSH jail Fail2Ban активен"
}

configure_journald() {
    ((ENABLE_JOURNAL)) || return 0
    {
        cat <<'EOF'
# Managed by Secure Linux Wizard
[Journal]
Storage=persistent
Compress=yes
Seal=yes
SystemMaxUse=500M
MaxRetentionSec=1month
EOF
    } | put_file /etc/systemd/journald.conf.d/90-secure-linux-wizard.conf 644 root root
    ((DRY_RUN)) && return 0
    if getent group systemd-journal >/dev/null 2>&1; then
        install -d -o root -g systemd-journal -m 2755 /var/log/journal
    else
        install -d -o root -g root -m 2755 /var/log/journal
    fi
    run systemctl restart systemd-journald
}

configure_updates() {
    ((ENABLE_UPDATES)) || return 0
    if [[ "$OS_FAMILY" == "debian" ]]; then
        {
            cat <<'EOF'
// Managed by Secure Linux Wizard
APT::Periodic::Enable "1";
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "false";
EOF
        } | put_file /etc/apt/apt.conf.d/52-secure-linux-wizard 644 root root
        ((DRY_RUN)) || {
            run systemctl enable --now apt-daily.timer apt-daily-upgrade.timer
            unattended-upgrade --dry-run --debug >/dev/null || warn "unattended-upgrades dry-run reported a warning / dry-run unattended-upgrades сообщил предупреждение"
        }
    elif command_exists dnf-automatic; then
        backup_path /etc/dnf/automatic.conf
        if ((DRY_RUN)); then
            info "Would configure dnf-automatic security updates"
        else
            sed -ri 's/^[[:space:]]*upgrade_type[[:space:]]*=.*/upgrade_type = security/' /etc/dnf/automatic.conf
            sed -ri 's/^[[:space:]]*apply_updates[[:space:]]*=.*/apply_updates = yes/' /etc/dnf/automatic.conf
            run systemctl enable --now dnf-automatic.timer
        fi
    else
        warn "dnf-automatic is unavailable; automatic updates were not enabled / dnf-automatic недоступен"
    fi
}

configure_password_policy() {
    ((ENABLE_PASSWORD_POLICY)) || return 0
    if [[ -d /etc/security/pwquality.conf.d ]]; then
        {
            cat <<'EOF'
# Managed by Secure Linux Wizard. Applies to future password changes.
minlen = 14
minclass = 3
maxrepeat = 3
maxsequence = 4
dictcheck = 1
usercheck = 1
retry = 3
EOF
        } | put_file /etc/security/pwquality.conf.d/90-secure-linux-wizard.conf 644 root root
    else
        warn "pwquality drop-in directory is unavailable; password policy was not changed / Нет каталога pwquality.d"
    fi
    local sudo_tmp
    sudo_tmp="$(mktemp)"
    {
        cat <<'EOF'
# Managed by Secure Linux Wizard
Defaults use_pty
Defaults passwd_tries=3
EOF
    } > "$sudo_tmp"
    if ((DRY_RUN==0)); then visudo -cf "$sudo_tmp" >/dev/null; fi
    put_file /etc/sudoers.d/90-secure-linux-wizard 440 root root < "$sudo_tmp"
    rm -f "$sudo_tmp"
}

configure_sysctl() {
    ((ENABLE_SYSCTL)) || return 0
    local tmp key value pair
    local settings=(
        'kernel.randomize_va_space=2'
        'kernel.kptr_restrict=2'
        'kernel.dmesg_restrict=1'
        'kernel.yama.ptrace_scope=1'
        'fs.protected_hardlinks=1'
        'fs.protected_symlinks=1'
        'fs.protected_fifos=1'
        'fs.protected_regular=2'
        'net.ipv4.tcp_syncookies=1'
        'net.ipv4.conf.all.accept_redirects=0'
        'net.ipv4.conf.default.accept_redirects=0'
        'net.ipv4.conf.all.accept_source_route=0'
        'net.ipv4.conf.default.accept_source_route=0'
        'net.ipv6.conf.all.accept_redirects=0'
        'net.ipv6.conf.default.accept_redirects=0'
        'net.ipv6.conf.all.accept_source_route=0'
        'net.ipv6.conf.default.accept_source_route=0'
    )
    tmp="$(mktemp)"
    printf '# Managed by Secure Linux Wizard %s\n' "$SCRIPT_VERSION" > "$tmp"
    printf '# Deliberately does not change forwarding, rp_filter, NAT, or IPv6 availability.\n' >> "$tmp"
    for pair in "${settings[@]}"; do
        key="${pair%%=*}"; value="${pair#*=}"
        if sysctl -n "$key" >/dev/null 2>&1; then
            if ((DRY_RUN)); then
                printf '%s = %s\n' "$key" "$value" >> "$tmp"
            elif sysctl -w "$key=$value" >/dev/null 2>&1; then
                printf '%s = %s\n' "$key" "$value" >> "$tmp"
            else
                warn "Skipped unwritable sysctl: $key"
            fi
        fi
    done
    if ((DRY_RUN)); then
        info "Would write compatible sysctl profile / Будет записан совместимый sysctl-профиль"
        rm -f "$tmp"
    else
        backup_path /etc/sysctl.d/90-secure-linux-wizard.conf
        install --remove-destination -m 644 -o root -g root "$tmp" /etc/sysctl.d/90-secure-linux-wizard.conf
        rm -f "$tmp"
        sysctl -p /etc/sysctl.d/90-secure-linux-wizard.conf >/dev/null
    fi
}

configure_audit_tools() {
    ((ENABLE_AUDIT_TOOLS)) || return 0
    if command_exists auditctl; then
        run_optional systemctl enable auditd || true
        run_optional systemctl start auditd || true
    fi
    if command_exists lynis; then
        info "Lynis installed. Run later: sudo lynis audit system / Lynis установлен; аудит: sudo lynis audit system"
    fi
}

enable_time_sync() {
    if unit_exists systemd-timesyncd.service; then
        run_optional systemctl enable --now systemd-timesyncd || true
    elif unit_exists chronyd.service; then
        run_optional systemctl enable --now chronyd || true
    elif unit_exists chrony.service; then
        run_optional systemctl enable --now chrony || true
    else
        warn "No supported time-sync service was found / Служба синхронизации времени не найдена"
    fi
}

print_plan() {
    printf '\n%s%s%s\n' "$bold" "$(t preflight_title)" "$reset"
    printf '  OS: %s %s (%s)\n' "$OS_ID" "$OS_VERSION" "$OS_FAMILY"
    printf '  Interface: %s\n' "${PUBLIC_IFACE:-unknown}"
    printf '  SSH: %s -> %s; users: %s; tunnels: %s\n' "$CURRENT_SSH_PORT" "$SSH_PORT" "$ALLOW_USERS" "$ALLOW_SSH_TUNNELS"
    printf '  TCP: %s\n  UDP: %s\n' "${INBOUND_TCP:-none}" "${INBOUND_UDP:-none}"
    printf '  Docker=%s VPN=%s forwarding=%s\n' "$HAS_DOCKER" "$HAS_VPN" "$HAS_FORWARDING"
    printf '  firewall=%s fail2ban=%s updates=%s journal=%s sysctl=%s audit=%s password-policy=%s\n' \
        "$ENABLE_FIREWALL" "$ENABLE_FAIL2BAN" "$ENABLE_UPDATES" "$ENABLE_JOURNAL" "$ENABLE_SYSCTL" "$ENABLE_AUDIT_TOOLS" "$ENABLE_PASSWORD_POLICY"
    printf '  automatic reboot: NO\n\n'
}

collect_server_answers() {
    local suggested_admin suggested_tcp suggested_udp raw
    suggested_admin="${SUDO_USER:-admin}"
    [[ "$suggested_admin" != "root" ]] || suggested_admin="admin"
    ADMIN_USER="$(ask "$(t admin_user)" "$suggested_admin")"
    validate_user "$ADMIN_USER" || die "Invalid administrator / Недопустимый администратор: $ADMIN_USER"
    [[ "$ADMIN_USER" != "root" ]] || die "Use a non-root administrator / Используйте администратора не root"
    raw="$(ask "$(t ssh_users)" "$ADMIN_USER")"; ALLOW_USERS="$(validate_user_list "$raw")"
    SSH_PORT="$(ask "$(t ssh_port)" "$CURRENT_SSH_PORT")"; validate_port "$SSH_PORT" || die "Invalid SSH port / Недопустимый порт SSH"
    suggested_tcp="$(public_listeners t || true)"
    suggested_udp="$(public_listeners u || true)"
    INBOUND_TCP="$(normalize_csv_ports "$(ask "$(t tcp_ports)" "$suggested_tcp")")"
    INBOUND_UDP="$(normalize_csv_ports "$(ask "$(t udp_ports)" "$suggested_udp")")"
    TRUSTED_CIDRS="$(ask "$(t trusted_cidrs)" "")"
    [[ "$TRUSTED_CIDRS" =~ ^[0-9A-Fa-f:.\ /]*$ ]] || die "Invalid trusted CIDR list / Неверный список CIDR"
    if confirm "$(t ssh_tunnels)" no; then ALLOW_SSH_TUNNELS=1; else ALLOW_SSH_TUNNELS=0; fi
    confirm "$(t feature_firewall)" yes && ENABLE_FIREWALL=1 || ENABLE_FIREWALL=0
    confirm "$(t feature_f2b)" yes && ENABLE_FAIL2BAN=1 || ENABLE_FAIL2BAN=0
    confirm "$(t feature_updates)" yes && ENABLE_UPDATES=1 || ENABLE_UPDATES=0
    confirm "$(t feature_journal)" yes && ENABLE_JOURNAL=1 || ENABLE_JOURNAL=0
    confirm "$(t feature_sysctl)" yes && ENABLE_SYSCTL=1 || ENABLE_SYSCTL=0
    confirm "$(t feature_audit)" yes && ENABLE_AUDIT_TOOLS=1 || ENABLE_AUDIT_TOOLS=0
    confirm "$(t feature_passwords)" yes && ENABLE_PASSWORD_POLICY=1 || ENABLE_PASSWORD_POLICY=0
}

section() { printf '\n%s-- %s --%s\n' "$bold" "$*" "$reset"; }

audit_server() {
    local file
    detect_server
    printf '\n%s===== %s =====%s\n' "$bold" "$(t audit_title)" "$reset"
    printf 'UTC: %s\nHost: %s\nOS: %s %s\nKernel: %s\nInterface: %s\n' \
        "$(ts)" "$(hostname -f 2>/dev/null || hostname)" "$OS_ID" "$OS_VERSION" "$(uname -r)" "${PUBLIC_IFACE:-unknown}"

    section 'Failed systemd units / Неисправные systemd-службы'
    systemctl --failed --no-pager || true

    section 'SSH effective configuration / Эффективная конфигурация SSH'
    sshd -T 2>/dev/null | grep -Ei '^(port|permitrootlogin|pubkeyauthentication|passwordauthentication|kbdinteractiveauthentication|authenticationmethods|maxauthtries|logingracetime|allowusers|allowgroups|x11forwarding|allowagentforwarding|allowtcpforwarding|allowstreamlocalforwarding|gatewayports|permittunnel)[[:space:]]' || true

    section 'Authorized key fingerprints / Отпечатки разрешённых ключей'
    shopt -s nullglob
    for file in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
        [[ -s "$file" ]] || continue
        printf '=== %s (%s %s) ===\n' "$file" "$(stat -c '%a' "$file" 2>/dev/null || stat -f '%Lp' "$file" 2>/dev/null || true)" "$(stat -c '%U:%G' "$file" 2>/dev/null || true)"
        ssh-keygen -lf "$file" 2>/dev/null || warn "Cannot parse some lines in $file / Некоторые строки ключей не распознаны"
    done
    shopt -u nullglob

    section 'Firewall / Межсетевой экран'
    if command_exists ufw; then ufw status verbose || true; fi
    if command_exists firewall-cmd; then firewall-cmd --state || true; firewall-cmd --list-all || true; fi

    section 'Fail2Ban'
    systemctl is-active fail2ban 2>/dev/null || true
    if command_exists fail2ban-client && fail2ban-client ping >/dev/null 2>&1; then
        fail2ban-client status || true
        fail2ban-client status sshd || true
    fi

    section 'Listening sockets / Слушающие порты'
    ss -lntup || true
    printf '\nPublic TCP: %s\nPublic UDP: %s\n' "$(public_listeners t || true)" "$(public_listeners u || true)"

    section 'Critical services / Критичные службы'
    for file in "$SSH_SERVICE" nginx apache2 httpd docker postgresql fail2ban auditd systemd-journald; do
        if unit_exists "${file}.service"; then printf '%-24s %s\n' "$file" "$(systemctl is-active "$file" 2>/dev/null || true)"; fi
    done

    section 'Automatic updates / Автоматические обновления'
    if [[ "$OS_FAMILY" == "debian" ]]; then
        systemctl is-enabled apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true
        systemctl is-active apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true
        apt-config dump 2>/dev/null | grep -E 'APT::Periodic|Unattended-Upgrade::Automatic-Reboot' || true
    else
        systemctl is-enabled dnf-automatic.timer 2>/dev/null || true
        systemctl is-active dnf-automatic.timer 2>/dev/null || true
    fi

    section 'Kernel baseline / Базовые параметры ядра'
    sysctl \
        kernel.randomize_va_space kernel.kptr_restrict kernel.dmesg_restrict kernel.yama.ptrace_scope \
        fs.protected_hardlinks fs.protected_symlinks fs.protected_fifos fs.protected_regular \
        net.ipv4.ip_forward net.ipv6.conf.all.forwarding net.ipv4.tcp_syncookies \
        net.ipv4.conf.all.accept_redirects net.ipv6.conf.all.accept_redirects 2>/dev/null || true

    section 'MAC and auditing / MAC и аудит'
    systemctl is-active apparmor 2>/dev/null || true
    if command_exists aa-status; then aa-status 2>/dev/null | head -n 35 || true; fi
    if command_exists getenforce; then getenforce || true; fi
    systemctl is-active auditd 2>/dev/null || true
    if command_exists lynis; then lynis show version 2>/dev/null || true; fi

    section 'Docker containers and published ports / Docker-контейнеры и опубликованные порты'
    if command_exists docker && systemctl is-active --quiet docker 2>/dev/null; then
        docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Ports}}\t{{.Status}}' || true
        printf '\nPrivileged containers / Привилегированные контейнеры:\n'
        for file in $(docker ps --format '{{.Names}}'); do
            [[ "$(docker inspect -f '{{.HostConfig.Privileged}}' "$file" 2>/dev/null)" == "true" ]] && printf '%s\n' "$file"
        done
    else
        printf 'not active / не активен\n'
    fi

    section 'Secret-file permissions (content is never shown) / Права файлов секретов (без содержимого)'
    find /etc /opt /srv /var/www -xdev -type f \
        \( -name '.env' -o -name '*.env' -o -name '*credential*' -o -name '*secret*' \) \
        -perm /004 -printf 'WORLD-READABLE %m %u:%g %p\n' 2>/dev/null | head -n 100 || true

    section 'Recent logins / Последние входы'
    last -n 15 2>/dev/null || true

    section 'Reboot status / Статус перезагрузки'
    [[ -e /var/run/reboot-required ]] && cat /var/run/reboot-required || printf 'not requested / не требуется\n'
    printf '\n%s===== END / КОНЕЦ =====%s\n' "$bold" "$reset"
}

client_write_profile() {
    local alias="$1" host="$2" user="$3" port="$4" key_path="$5"
    local ssh_dir="$HOME/.ssh" config="$HOME/.ssh/config" drop_dir="$HOME/.ssh/config.d" profile="$HOME/.ssh/config.d/${alias}.conf" tmp
    mkdir -p "$ssh_dir" "$drop_dir"; chmod 700 "$ssh_dir" "$drop_dir"
    if [[ -e "$config" ]]; then cp -a "$config" "$config.backup-${STAMP}"; else : > "$config"; chmod 600 "$config"; fi
    if ! head -n 5 "$config" 2>/dev/null | grep -Eq '^[[:space:]]*Include[[:space:]]+~/.ssh/config\.d/\*'; then
        tmp="$(mktemp)"
        { printf 'Include ~/.ssh/config.d/*\n'; cat "$config"; } > "$tmp"
        install -m 600 "$tmp" "$config"; rm -f "$tmp"
    fi
    {
        printf 'Host %s\n' "$alias"
        printf '    HostName %s\n' "$host"
        printf '    User %s\n' "$user"
        printf '    Port %s\n' "$port"
        printf '    IdentityFile %s\n' "$key_path"
        printf '    IdentitiesOnly yes\n'
        printf '    AddKeysToAgent yes\n'
        [[ "$(uname -s)" == "Darwin" ]] && printf '    UseKeychain yes\n'
        printf '    ServerAliveInterval 60\n'
        printf '    ServerAliveCountMax 3\n'
    } > "$profile"
    chmod 600 "$profile"
}

setup_client_agent() {
    local key_path="$1" state_dir agent_env
    info "$(t agent_note)"
    if [[ "$(uname -s)" == "Darwin" ]]; then
        ssh-add --apple-use-keychain "$key_path" 2>/dev/null || ssh-add "$key_path" || warn "ssh-add failed / ssh-add завершился ошибкой"
        return 0
    fi
    state_dir="${XDG_STATE_HOME:-$HOME/.local/state}/secure-linux-wizard"; mkdir -p "$state_dir"; chmod 700 "$state_dir"
    agent_env="$state_dir/ssh-agent.env"
    if [[ -z "${SSH_AUTH_SOCK:-}" || ! -S "${SSH_AUTH_SOCK:-/nonexistent}" ]]; then
        if ! ssh-agent -s > "$agent_env"; then
            rm -f "$agent_env"
            warn "Could not start ssh-agent; start it manually before connecting / Не удалось запустить ssh-agent; запустите его вручную"
            return 0
        fi
        chmod 600 "$agent_env"
        # shellcheck disable=SC1090
        . "$agent_env"
        info "For later shells run / Для новых терминалов: source '$agent_env'"
    fi
    ssh-add "$key_path" || warn "ssh-add failed / ssh-add завершился ошибкой"
}

admin_pc_wizard() {
    command_exists ssh || die "OpenSSH client is required / Требуется клиент OpenSSH"
    command_exists ssh-keygen || die "ssh-keygen is required / Требуется ssh-keygen"
    local alias host user port key_path default_key comment
    alias="$(ask "$(t client_alias)" myvps)"
    [[ "$alias" =~ ^[A-Za-z0-9._-]+$ ]] || die "Invalid alias / Недопустимое имя подключения"
    host="$(ask "$(t server_host)" "")"; [[ -n "$host" && "$host" != *[[:space:]]* ]] || die "Server host is required / Укажите адрес сервера"
    user="$(ask "$(t server_user)" admin)"; validate_user "$user" || die "Invalid SSH user / Недопустимый SSH-пользователь"
    port="$(ask "$(t ssh_port)" 22)"; validate_port "$port" || die "Invalid port / Недопустимый порт"
    default_key="$HOME/.ssh/${alias}_ed25519"
    key_path="$(ask "$(t key_path)" "$default_key")"; key_path="${key_path/#\~/$HOME}"
    if ((DRY_RUN)); then
        info "Would prepare SSH key/profile / Будут подготовлены SSH-ключ и профиль: $key_path, Host $alias"
        info "Would offer to copy only ${key_path}.pub to $user@$host:$port / Будет предложено скопировать только открытый ключ"
        ok "Admin's PC dry-run complete / Dry-run ПК администратора завершён"
        return 0
    fi
    mkdir -p "$(dirname "$key_path")"; chmod 700 "$(dirname "$key_path")"
    if [[ ! -f "$key_path" ]]; then
        confirm "$(t generate_key)" yes || die "A private key is required / Требуется приватный ключ"
        comment="${USER:-admin}@$(hostname -s 2>/dev/null || hostname)-${alias}"
        printf '\n%s\n' "$(t agent_note)"
        ssh-keygen -t ed25519 -a 100 -f "$key_path" -C "$comment"
    fi
    [[ -f "$key_path.pub" ]] || ssh-keygen -y -f "$key_path" > "$key_path.pub"
    chmod 600 "$key_path"; chmod 644 "$key_path.pub"
    ssh-keygen -lf "$key_path.pub"
    client_write_profile "$alias" "$host" "$user" "$port" "$key_path"
    setup_client_agent "$key_path"
    if confirm "$(t copy_key)" yes; then
        if command_exists ssh-copy-id; then
            ssh-copy-id -i "$key_path.pub" -p "$port" "$user@$host"
        else
            ssh -p "$port" "$user@$host" \
                'umask 077; mkdir -p ~/.ssh; touch ~/.ssh/authorized_keys; chmod 700 ~/.ssh; chmod 600 ~/.ssh/authorized_keys; IFS= read -r key; grep -qxF -- "$key" ~/.ssh/authorized_keys || printf "%s\n" "$key" >> ~/.ssh/authorized_keys' \
                < "$key_path.pub"
        fi
    fi
    if ssh -o BatchMode=yes -o IdentitiesOnly=yes -i "$key_path" -p "$port" "$user@$host" true; then
        ok "SSH key login works / Вход по SSH-ключу работает"
    else
        warn "Automatic non-interactive test failed. Try manually: ssh $alias / Автотест не прошёл; проверьте вручную: ssh $alias"
    fi
    ok "$(t client_done "$alias")"
}

health_check() {
    ((DRY_RUN)) && return 0
    sshd -t
    systemctl is-active --quiet "$SSH_SERVICE" || die "SSH service is not active / SSH-служба не активна"
    ((ENABLE_FIREWALL)) && {
        if [[ "$FIREWALL_KIND" == "ufw" ]]; then ufw status | grep -q '^Status: active'; else firewall-cmd --state | grep -q running; fi
    }
    ((ENABLE_FAIL2BAN)) && fail2ban-client ping >/dev/null
    systemctl --failed --no-legend --plain | grep -vE '(^|[[:space:]])(dnf-makecache|apt-daily)' > "$BACKUP_DIR/failed-units-after.txt" || true
}

run_server_wizard() {
    detect_server
    warn "$(t keep_session)"
    if ((DRY_RUN==0)); then
        if ((ASSUME_YES)) && ((SNAPSHOT_CONFIRMED==0)); then
            die "--yes requires --snapshot-confirmed / Для --yes требуется --snapshot-confirmed"
        fi
        if ((SNAPSHOT_CONFIRMED==0)) && ! confirm "$(t snapshot_confirm)" no; then
            die "$(t abort_snapshot)"
        fi
    fi
    collect_server_answers
    print_plan
    confirm "$(t confirm_plan)" yes || exit 0
    prepare_backup
    install_self
    install_required_packages
    ensure_admin_user
    provision_admin_key
    configure_firewall
    write_ssh_config 0
    write_pending_ssh_state
    configure_journald
    configure_updates
    configure_fail2ban
    enable_time_sync
    configure_sysctl
    configure_password_policy
    configure_audit_tools
    health_check

    if ((KEY_READY)); then
        printf '\n%s\n  ssh -p %s %s@SERVER_IP_OR_NAME\n  sudo -v\n\n' "$(t test_second)" "$SSH_PORT" "$ADMIN_USER"
        if confirm "$(t did_test)" no; then
            write_ssh_config 1
            ((DRY_RUN)) || rm -f "$PENDING_SSH_FILE"
            ok "$(t lockdown_done)"
        else
            warn "$(t lockdown_pending)"
        fi
    else
        warn "$(t lockdown_pending)"
    fi

    if ((DRY_RUN==0)); then
        cp -a "$LOG_FILE" "$BACKUP_DIR/run.log" 2>/dev/null || true
        printf '%s\n' "$ADMIN_USER" > "$BACKUP_DIR/admin-user.txt"
        printf '%s\n' "$SSH_PORT" > "$BACKUP_DIR/ssh-port.txt"
    fi
    ok "$(t complete)"
    if ((DRY_RUN)); then
        info "Dry-run created no recovery point / В dry-run точка восстановления не создаётся"
    else
        ok "$(t backup_at)"
    fi
    [[ -e /var/run/reboot-required ]] && warn "$(t reboot_needed)"
    printf '\nAudit / Аудит:\n  sudo secure-linux-wizard --audit --lang %s\n' "$LANGUAGE"
    if ((DRY_RUN==0)); then
        printf 'Rollback / Откат:\n  sudo secure-linux-wizard --rollback %q --lang %s\n' "$BACKUP_DIR" "$LANGUAGE"
    fi
}

main() {
    choose_language
    choose_role
    if [[ "$ROLE" == "server" ]]; then
        [[ ${EUID:-$(id -u)} -eq 0 ]] || die "$(t need_root)"
        if [[ "$ACTION" != "audit" && "$DRY_RUN" -eq 0 ]]; then
            [[ -d /run/lock ]] || install -d -o root -g root -m 755 /run/lock
            exec 9>/run/lock/secure-linux-wizard.lock
            flock -n 9 || die "Another instance is running / Уже запущен другой экземпляр"
        fi
    fi
    init_log
    case "$ACTION:$ROLE" in
        rollback:server) rollback_files "$ROLLBACK_DIR" ;;
        audit:server) audit_server ;;
        finalize:server) finalize_ssh ;;
        wizard:server) run_server_wizard ;;
        wizard:admin) admin_pc_wizard ;;
        *) die "Unsupported action / Неподдерживаемое действие: $ACTION:$ROLE" ;;
    esac
}

main
