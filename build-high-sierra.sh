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

# "legacy" is a Fyne build tag, not a Picocrypt one. It excludes
# fyne/app/app_notlegacy_darwin.go, whose entire content is
#   #cgo LDFLAGS: -framework Foundation -framework UserNotifications
# UserNotifications.framework first shipped in macOS 10.14, so without this tag
# the link fails here with "framework not found UserNotifications". Fyne's
# app_darwin.m already guards the matching ObjC code behind
# __MAC_OS_X_VERSION_MAX_ALLOWED >= 101400 and falls back to the pre-10.14
# notification path, so dropping the framework costs nothing on 10.13.
#
# Note this tag is *required* on a 10.13 SDK and *breaks* on a 10.14+ SDK, where
# app_darwin.m compiles the UserNotifications path and then needs the framework.
BUILD_TAGS="legacy"
if [ "${1:-}" = "cli" ]; then
	BUILD_TAGS="legacy,cli"
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
echo "Tags:      $BUILD_TAGS"

go build -tags "$BUILD_TAGS" -ldflags="-s -w" -o "$OUTPUT" ./cmd/picocrypt

echo
echo "Built src/$OUTPUT"
./"$OUTPUT" --version
