#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
VERSION="${VERSION:-$(cat "$ROOT/VERSION")}"
DIST="$ROOT/dist"
PAYLOAD_DIR="$ROOT/internal/serverpayload/bin"

case "$VERSION" in
  *[!0-9A-Za-z.-]*|'')
    echo "Недопустимая версия: $VERSION" >&2
    exit 64
    ;;
esac

for command_name in go npm sha256sum; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "$command_name не найден в PATH" >&2
    exit 69
  }
done

mkdir -p "$DIST" "$PAYLOAD_DIR"
cd "$ROOT"

npm --prefix ui/windows ci
npm --prefix ui/windows test
node --test scripts/release.test.mjs
npm --prefix ui/windows run build

build_payload() {
  target_arch=$1
  CGO_ENABLED=0 GOOS=linux GOARCH="$target_arch" \
    go build -trimpath -buildvcs=false \
    -ldflags "-s -w -X main.version=$VERSION" \
    -o "$PAYLOAD_DIR/bastionctl-server-ubuntu-$target_arch" ./cmd/bastionctl
}

build_payload amd64
build_payload arm64

CGO_ENABLED=0 go test ./...
CGO_ENABLED=0 go vet ./...

CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
  go build -tags production -trimpath -buildvcs=false \
  -ldflags "-s -w -H=windowsgui -X main.version=$VERSION" \
  -o "$DIST/bastionctl.exe" ./cmd/bastionctl-desktop

desktop_size=$(wc -c < "$DIST/bastionctl.exe")
if [ "$desktop_size" -lt 20000000 ]; then
  echo "Windows-файл слишком мал: production Wails или Ubuntu payload не встроены" >&2
  exit 70
fi

archive="bastionctl-$VERSION-source.tar.gz"
tar \
  --sort=name \
  --mtime='UTC 2020-01-01' \
  --owner=0 --group=0 --numeric-owner \
  --exclude='./dist' \
  --exclude='./.git' \
  --exclude='./ui/windows/node_modules' \
  --exclude='./internal/serverpayload/bin' \
  --transform="s,^\./,bastionctl-$VERSION/," \
  -czf "$DIST/$archive" .

(
  cd "$DIST"
  sha256sum \
    bastionctl.exe \
    "$archive" > SHA256SUMS
  sha256sum -c SHA256SUMS
)

echo "Сборка bastionctl $VERSION завершена: $DIST"
