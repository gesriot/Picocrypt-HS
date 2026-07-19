#!/bin/bash
# Build Picocrypt-HS for Intel macOS 10.13 High Sierra.
#
# Run this on the 10.13 machine itself, with Go 1.20.x installed (Go 1.21 and
# later require macOS 10.15, so 1.20 is the newest usable toolchain here).
#
#   ./build-high-sierra.sh          # GUI + CLI build (default)
#   ./build-high-sierra.sh cli      # CLI-only, no graphics dependencies
#
# The result is src/Picocrypt-HS.

set -euo pipefail

cd "$(dirname "$0")/src"

OUTPUT="Picocrypt-HS"
BUILD_TAGS=""
if [ "${1:-}" = "cli" ]; then
	BUILD_TAGS="cli"
	echo "Building CLI-only (no Fyne/OpenGL)."
else
	echo "Building GUI + CLI."
fi

# Refuse to run under a toolchain that cannot target 10.13, and never let Go
# download a newer one behind our back.
export GOTOOLCHAIN=local
GO_VERSION="$(go env GOVERSION)"
case "$GO_VERSION" in
go1.20*) ;;
*)
	echo "error: found $GO_VERSION, but this fork needs Go 1.20.x." >&2
	echo "Go 1.21+ requires macOS 10.15 and will not run here." >&2
	exit 1
	;;
esac

export CGO_ENABLED=1
export MACOSX_DEPLOYMENT_TARGET=10.13
export CGO_CFLAGS="-mmacosx-version-min=10.13"
export CGO_LDFLAGS="-mmacosx-version-min=10.13"

echo "Toolchain: $GO_VERSION"
echo "Target:    macOS 10.13, $(go env GOARCH)"

if [ -n "$BUILD_TAGS" ]; then
	go build -tags "$BUILD_TAGS" -ldflags="-s -w" -o "$OUTPUT" ./cmd/picocrypt
else
	go build -ldflags="-s -w" -o "$OUTPUT" ./cmd/picocrypt
fi

echo
echo "Built src/$OUTPUT"
./"$OUTPUT" --version
