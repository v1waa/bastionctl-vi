#!/bin/sh
set -eu

VERSION="${VERSION:-1.2.0}"
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
DIST="$ROOT/dist"

case "$VERSION" in
  *[!0-9A-Za-z.-]*|'')
    echo "Недопустимая версия: $VERSION" >&2
    exit 64
    ;;
esac

command -v go >/dev/null 2>&1 || {
  echo "Go toolchain не найден в PATH" >&2
  exit 69
}
command -v sha256sum >/dev/null 2>&1 || {
  echo "sha256sum не найден" >&2
  exit 69
}

mkdir -p "$DIST"
cd "$ROOT"

CGO_ENABLED=0 go test ./...
CGO_ENABLED=0 go vet ./...

build_one() {
  target_os=$1
  target_arch=$2
  output=$3
  CGO_ENABLED=0 GOOS="$target_os" GOARCH="$target_arch" \
    go build -trimpath -buildvcs=false \
    -ldflags "-s -w -X main.version=$VERSION" \
    -o "$DIST/$output" ./cmd/bastionctl
}

build_one linux amd64 bastionctl-linux-amd64
build_one linux arm64 bastionctl-linux-arm64
build_one windows amd64 bastionctl-windows-amd64.exe
build_one darwin arm64 bastionctl-darwin-arm64
build_one darwin amd64 bastionctl-darwin-amd64

bundle="bastionctl-$VERSION-admin-bundle.tar.gz"
tar \
  --sort=name \
  --mtime='UTC 2020-01-01' \
  --owner=0 --group=0 --numeric-owner \
  --transform="s,^,bastionctl-$VERSION/," \
  -czf "$DIST/$bundle" \
  -C "$DIST" \
    bastionctl-linux-amd64 \
    bastionctl-linux-arm64 \
    bastionctl-windows-amd64.exe \
    bastionctl-darwin-arm64 \
    bastionctl-darwin-amd64 \
  -C "$ROOT" \
    README.md \
    SECURITY.md \
    config.example.toml \
    LICENSE

archive="bastionctl-$VERSION-source.tar.gz"
tar \
  --sort=name \
  --mtime='UTC 2020-01-01' \
  --owner=0 --group=0 --numeric-owner \
  --exclude='./dist' \
  --exclude='./.git' \
  --transform="s,^\./,bastionctl-$VERSION/," \
  -czf "$DIST/$archive" .

(
  cd "$DIST"
  sha256sum \
    bastionctl-linux-amd64 \
    bastionctl-linux-arm64 \
    bastionctl-windows-amd64.exe \
    bastionctl-darwin-arm64 \
    bastionctl-darwin-amd64 \
    "$bundle" \
    "$archive" > SHA256SUMS
  sha256sum -c SHA256SUMS
)

echo "Сборка bastionctl $VERSION завершена: $DIST"
