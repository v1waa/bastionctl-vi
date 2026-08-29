#!/bin/sh
set -eu

VERSION="${VERSION:-2.0.0}"
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
DIST="$ROOT/dist"

case "$VERSION" in
  *[!0-9A-Za-z.-]*|'')
    echo "Недопустимая версия: $VERSION" >&2
    exit 64
    ;;
esac

for command_name in go npm sha256sum zip; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "$command_name не найден в PATH" >&2
    exit 69
  }
done

mkdir -p "$DIST"
cd "$ROOT"

CGO_ENABLED=0 go test ./...
CGO_ENABLED=0 go vet ./...
npm --prefix ui/windows ci
npm --prefix ui/windows run build

CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
  go build -trimpath -buildvcs=false \
  -ldflags "-s -w -H=windowsgui -X main.version=$VERSION" \
  -o "$DIST/bastionctl-admin-windows-amd64.exe" ./cmd/bastionctl-desktop

build_server() {
  target_arch=$1
  CGO_ENABLED=0 GOOS=linux GOARCH="$target_arch" \
    go build -trimpath -buildvcs=false \
    -ldflags "-s -w -X main.version=$VERSION" \
    -o "$DIST/bastionctl-server-ubuntu-$target_arch" ./cmd/bastionctl
}

build_server amd64
build_server arm64

release_stage=$(mktemp -d "$DIST/.release-XXXXXX")
trap 'rm -rf "$release_stage"' EXIT HUP INT TERM
bundle_directory="$release_stage/bastionctl-$VERSION"
mkdir -p "$bundle_directory"
cp "$DIST/bastionctl-admin-windows-amd64.exe" "$bundle_directory/"
cp "$DIST/bastionctl-server-ubuntu-amd64" "$bundle_directory/"
cp "$DIST/bastionctl-server-ubuntu-arm64" "$bundle_directory/"
cp README.md SECURITY.md config.example.toml LICENSE "$bundle_directory/"
find "$bundle_directory" -exec touch -t 202001010000 {} +

bundle="bastionctl-$VERSION-windows-ubuntu.zip"
(
  cd "$release_stage"
  zip -X -q -r "$bundle" "bastionctl-$VERSION"
)
mv -f "$release_stage/$bundle" "$DIST/$bundle"

archive="bastionctl-$VERSION-source.tar.gz"
tar \
  --sort=name \
  --mtime='UTC 2020-01-01' \
  --owner=0 --group=0 --numeric-owner \
  --exclude='./dist' \
  --exclude='./.git' \
  --exclude='./ui/windows/node_modules' \
  --transform="s,^\./,bastionctl-$VERSION/," \
  -czf "$DIST/$archive" .

(
  cd "$DIST"
  sha256sum \
    bastionctl-admin-windows-amd64.exe \
    bastionctl-server-ubuntu-amd64 \
    bastionctl-server-ubuntu-arm64 \
    "$bundle" \
    "$archive" > SHA256SUMS
  sha256sum -c SHA256SUMS
)

echo "Сборка bastionctl $VERSION завершена: $DIST"
