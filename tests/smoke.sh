#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'
umask 077

ROOT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
MAIN="$ROOT_DIR/secure-linux-wizard.sh"
TMP_ROOT="$(mktemp -d)"
SUDO=()
if ((EUID != 0)); then
    command -v sudo >/dev/null 2>&1 || { printf 'sudo is required for server dry-run tests\n' >&2; exit 1; }
    SUDO=(sudo)
fi

cleanup() {
    "${SUDO[@]}" rm -rf -- "$TMP_ROOT"
}
trap cleanup EXIT

pass() { printf 'ok - %s\n' "$*"; }
fail() { printf 'not ok - %s\n' "$*" >&2; exit 1; }
assert_contains() {
    local file="$1" value="$2"
    grep -Fq -- "$value" "$file" || { tail -n 80 "$file" >&2 || true; fail "missing expected text: $value"; }
}

bash -n "$ROOT_DIR"/*.sh
pass 'Bash syntax'

bash "$MAIN" --help > "$TMP_ROOT/help.txt"
assert_contains "$TMP_ROOT/help.txt" '--finalize-ssh'
assert_contains "$TMP_ROOT/help.txt" '--rollback DIR'
pass 'CLI help'

if bash "$MAIN" --role invalid --lang en --dry-run > "$TMP_ROOT/invalid-role.txt" 2>&1; then
    fail 'invalid role was accepted'
fi
assert_contains "$TMP_ROOT/invalid-role.txt" 'Invalid role'
pass 'invalid role rejection'

if bash "$MAIN" --role admin --lang invalid --dry-run > "$TMP_ROOT/invalid-language.txt" 2>&1; then
    fail 'invalid language was accepted'
fi
assert_contains "$TMP_ROOT/invalid-language.txt" 'Invalid language'
pass 'invalid language rejection'

"${SUDO[@]}" bash "$MAIN" --role server --lang en --dry-run --yes > "$TMP_ROOT/server-en.txt" 2>&1
assert_contains "$TMP_ROOT/server-en.txt" 'Complete. The server was not rebooted automatically.'
assert_contains "$TMP_ROOT/server-en.txt" 'Password/root login remains available.'
pass 'English server dry-run'

"${SUDO[@]}" bash "$MAIN" --role server --lang ru --dry-run --yes > "$TMP_ROOT/server-ru.txt" 2>&1
assert_contains "$TMP_ROOT/server-ru.txt" 'Готово. Сервер автоматически не перезагружался.'
assert_contains "$TMP_ROOT/server-ru.txt" 'Парольный/root-вход пока сохранён.'
pass 'Russian server dry-run'

set +e
printf 'admin\nadmin\n70000\n' \
    | "${SUDO[@]}" bash "$MAIN" --role server --lang en --dry-run > "$TMP_ROOT/invalid-port.txt" 2>&1
invalid_port_rc=$?
set -e
((invalid_port_rc != 0)) || fail 'invalid SSH port was accepted'
assert_contains "$TMP_ROOT/invalid-port.txt" 'Invalid SSH port'
pass 'invalid port rejection'

ADMIN_HOME="$TMP_ROOT/admin-home"
mkdir -p "$ADMIN_HOME"
if ! printf '\nexample.invalid\n\n\n\n' \
    | HOME="$ADMIN_HOME" USER='testadmin' bash "$MAIN" --role admin --lang en --dry-run > "$TMP_ROOT/admin-dry.txt" 2>&1; then
    tail -n 80 "$TMP_ROOT/admin-dry.txt" >&2 || true
    fail "Admin's PC dry-run failed"
fi
assert_contains "$TMP_ROOT/admin-dry.txt" "Admin's PC dry-run complete"
[[ ! -e "$ADMIN_HOME/.ssh" ]] || fail "Admin's PC dry-run created ~/.ssh"
[[ -z "$(find "$ADMIN_HOME" -mindepth 1 -print -quit)" ]] || fail "Admin's PC dry-run changed the test home"
pass "Admin's PC dry-run is non-mutating"

RECOVERY="$TMP_ROOT/recovery"
"${SUDO[@]}" install -d -o root -g root -m 700 "$RECOVERY/files" "$RECOVERY/absent"
printf '/etc/../tmp/secure-linux-wizard-path-traversal\n' \
    | "${SUDO[@]}" tee "$RECOVERY/manifest.txt" >/dev/null
"${SUDO[@]}" chown root:root "$RECOVERY/manifest.txt"
"${SUDO[@]}" chmod 600 "$RECOVERY/manifest.txt"
if "${SUDO[@]}" bash "$MAIN" --rollback "$RECOVERY" --dry-run --yes --lang en > "$TMP_ROOT/rollback.txt" 2>&1; then
    fail 'unsafe rollback manifest was accepted'
fi
assert_contains "$TMP_ROOT/rollback.txt" 'Unsafe manifest path'
pass 'rollback path traversal rejection'

if [[ -f "$ROOT_DIR/SHA256SUMS.txt" ]]; then
    (cd "$ROOT_DIR" && sha256sum -c SHA256SUMS.txt)
    pass 'SHA256SUMS integrity'
fi

if rg -n --hidden \
    -g '!SHA256SUMS.txt' -g '!tests/smoke.sh' \
    '(BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})' \
    "$ROOT_DIR" > "$TMP_ROOT/secrets.txt" 2>&1; then
    cat "$TMP_ROOT/secrets.txt" >&2
    fail 'private-key or token-like material found'
fi
pass 'basic secret-pattern scan'

printf '\nAll smoke tests passed. / Все smoke-тесты пройдены.\n'
