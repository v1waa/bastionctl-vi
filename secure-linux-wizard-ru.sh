#!/usr/bin/env bash
set -Eeuo pipefail
base_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
exec bash "$base_dir/secure-linux-wizard.sh" --lang ru "$@"
