#!/usr/bin/env bash
set -euo pipefail

APP_NAME="detectbot"
MAIN_PKG="./cmd/detectbot"
DIST_DIR="dist"

VERSION="1.1.3"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
BUILD_TIME="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

VERSION_SUFFIX="${VERSION//./_}"
LDFLAGS="-s -w -X main.Version=${VERSION} -X main.Commit=${COMMIT} -X main.BuildTime=${BUILD_TIME}"

rm -rf "${DIST_DIR}"
mkdir -p "${DIST_DIR}"

echo "==> go mod tidy"
go mod tidy

build_target() {
  local goos="$1"
  local goarch="$2"
  local ext="${3:-}"

  local output_name="${APP_NAME}_${goos}_${goarch}_v${VERSION_SUFFIX}${ext}"
  local output_path="${DIST_DIR}/${output_name}"

  echo "==> Building ${output_name}"
  GOOS="${goos}" GOARCH="${goarch}" CGO_ENABLED=0 \
    go build -trimpath -ldflags "${LDFLAGS}" -o "${output_path}" "${MAIN_PKG}"
}

# Windows
build_target "windows" "amd64" ".exe"

# Linux
build_target "linux" "amd64"

# macOS Intel
build_target "darwin" "amd64"

# macOS Apple Silicon
build_target "darwin" "arm64"

echo
echo "빌드 완료:"

ls -lh "${DIST_DIR}"
