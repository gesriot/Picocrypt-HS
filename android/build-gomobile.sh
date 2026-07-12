#!/bin/bash
# Build script for Go Mobile bindings
# This script builds the Go mobile AAR library for Android

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GO_SRC_DIR="$SCRIPT_DIR/../src"
OUTPUT_DIR="$SCRIPT_DIR/app/libs"
GOMOBILE_LDFLAGS="${GOMOBILE_LDFLAGS:--s -w -buildid=}"
NDK_VERSION_FILE="$SCRIPT_DIR/ndk-version.txt"
REQUIRED_GO_VERSION="go1.26.5"

# Set Android SDK/NDK paths
export ANDROID_HOME="${ANDROID_HOME:-/opt/android-sdk}"
export ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-$ANDROID_HOME}"

if [ ! -s "$NDK_VERSION_FILE" ]; then
    echo "Error: Android NDK version pin is missing or empty: $NDK_VERSION_FILE" >&2
    exit 1
fi
EXPECTED_NDK_VERSION="$(< "$NDK_VERSION_FILE")"
if [ -z "$EXPECTED_NDK_VERSION" ]; then
    echo "Error: Android NDK version pin is empty: $NDK_VERSION_FILE" >&2
    exit 1
fi

if [ -n "${ANDROID_NDK_HOME:-}" ]; then
    if [ ! -d "$ANDROID_NDK_HOME" ]; then
        echo "Error: ANDROID_NDK_HOME does not exist: $ANDROID_NDK_HOME" >&2
        exit 1
    fi
else
    export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/$EXPECTED_NDK_VERSION"
    if [ ! -d "$ANDROID_NDK_HOME" ]; then
        echo "Error: required Android NDK is not installed." >&2
        echo "  Expected version: $EXPECTED_NDK_VERSION" >&2
        echo "  Expected path: $ANDROID_NDK_HOME" >&2
        exit 1
    fi
fi

NDK_SOURCE_PROPERTIES="$ANDROID_NDK_HOME/source.properties"
if [ ! -f "$NDK_SOURCE_PROPERTIES" ]; then
    echo "Error: Android NDK metadata is missing: $NDK_SOURCE_PROPERTIES" >&2
    exit 1
fi
ACTUAL_NDK_VERSION="$(
    sed -n 's/^[[:space:]]*Pkg\.Revision[[:space:]]*=[[:space:]]*//p' "$NDK_SOURCE_PROPERTIES" \
        | head -n 1 \
        | tr -d '\r'
)"
if [ "$ACTUAL_NDK_VERSION" != "$EXPECTED_NDK_VERSION" ]; then
    echo "Error: Android NDK version mismatch." >&2
    echo "  Expected: $EXPECTED_NDK_VERSION" >&2
    echo "  Actual: ${ACTUAL_NDK_VERSION:-<missing>}" >&2
    echo "  Path: $ANDROID_NDK_HOME" >&2
    exit 1
fi
echo "Using NDK: $ANDROID_NDK_HOME ($ACTUAL_NDK_VERSION)"

if ! command -v go > /dev/null 2>&1; then
    echo "Error: go not found in PATH." >&2
    exit 1
fi
ACTUAL_GO_VERSION="$(go env GOVERSION)"
if [ "$ACTUAL_GO_VERSION" != "$REQUIRED_GO_VERSION" ]; then
    echo "Error: active Go version mismatch." >&2
    echo "  Expected: $REQUIRED_GO_VERSION" >&2
    echo "  Actual: ${ACTUAL_GO_VERSION:-<missing>}" >&2
    exit 1
fi
EXPECTED_MOBILE_VERSION="$(go -C "$GO_SRC_DIR" list -m -f '{{.Version}}' golang.org/x/mobile)"
if [ -z "$EXPECTED_MOBILE_VERSION" ]; then
    echo "Error: could not determine the required Go mobile toolchain version." >&2
    echo "  x/mobile: ${EXPECTED_MOBILE_VERSION:-<missing>}" >&2
    exit 1
fi

validate_mobile_tool() {
    local tool_name="$1"
    local expected_command_path="golang.org/x/mobile/cmd/$tool_name"
    local tool_path
    local metadata
    local actual_command_path
    local actual_module_path
    local actual_module_version
    local actual_go_version

    if ! tool_path="$(command -v "$tool_name")"; then
        echo "Error: $tool_name not found in PATH." >&2
        echo "  Install it with: go install $expected_command_path@$EXPECTED_MOBILE_VERSION" >&2
        return 1
    fi
    if ! metadata="$(go version -m "$tool_path" 2>&1)"; then
        echo "Error: could not inspect $tool_name build metadata." >&2
        echo "  Binary: $tool_path" >&2
        printf '%s\n' "$metadata" >&2
        return 1
    fi

    actual_command_path="$(printf '%s\n' "$metadata" | awk -F '\t' '$2 == "path" { print $3; exit }')"
    actual_module_path="$(printf '%s\n' "$metadata" | awk -F '\t' '$2 == "mod" { print $3; exit }')"
    actual_module_version="$(printf '%s\n' "$metadata" | awk -F '\t' '$2 == "mod" { print $4; exit }')"
    actual_go_version="$(printf '%s\n' "$metadata" | sed -n '1s/^.*: //p')"

    if [ "$actual_command_path" != "$expected_command_path" ]; then
        echo "Error: $tool_name command path mismatch." >&2
        echo "  Expected: $expected_command_path" >&2
        echo "  Actual: ${actual_command_path:-<missing>}" >&2
        echo "  Binary: $tool_path" >&2
        return 1
    fi
    if [ "$actual_module_path" != "golang.org/x/mobile" ]; then
        echo "Error: $tool_name module path mismatch." >&2
        echo "  Expected: golang.org/x/mobile" >&2
        echo "  Actual: ${actual_module_path:-<missing>}" >&2
        echo "  Binary: $tool_path" >&2
        return 1
    fi
    if [ "$actual_module_version" != "$EXPECTED_MOBILE_VERSION" ]; then
        echo "Error: $tool_name module version mismatch." >&2
        echo "  Expected: $EXPECTED_MOBILE_VERSION" >&2
        echo "  Actual: ${actual_module_version:-<missing>}" >&2
        echo "  Binary: $tool_path" >&2
        return 1
    fi
    if [ "$actual_go_version" != "$REQUIRED_GO_VERSION" ]; then
        echo "Error: $tool_name Go version mismatch." >&2
        echo "  Expected: $REQUIRED_GO_VERSION" >&2
        echo "  Actual: ${actual_go_version:-<missing>}" >&2
        echo "  Binary: $tool_path" >&2
        return 1
    fi

    echo "Validated $tool_name: $tool_path ($EXPECTED_MOBILE_VERSION, $REQUIRED_GO_VERSION)"
}

validate_mobile_tool gomobile
validate_mobile_tool gobind

# Always use API level 24 (matches app's minSdk)
USE_ANDROID_API="-androidapi 24"

echo "Building Go Mobile bindings for Android..."
echo "Go source directory: $GO_SRC_DIR"
echo "Output directory: $OUTPUT_DIR"
echo "Android SDK: $ANDROID_HOME"
echo "Android NDK: ${ANDROID_NDK_HOME:-not set}"
echo "Go linker flags: $GOMOBILE_LDFLAGS"

# Create output directory
mkdir -p "$OUTPUT_DIR"

REAL_GO="$(command -v go)"
REAL_GOBIND="$(command -v gobind)"
WRAPPER_DIR="$(mktemp -d)"
cleanup() {
    rm -rf "$WRAPPER_DIR"
}
trap cleanup EXIT

cat > "$WRAPPER_DIR/go" <<EOF
#!/bin/sh
set -e
if [ -n "\$GOFLAGS" ]; then
    export GOFLAGS="\$GOFLAGS -trimpath"
else
    export GOFLAGS="-trimpath"
fi
exec "$REAL_GO" "\$@"
EOF
chmod +x "$WRAPPER_DIR/go"

cat > "$WRAPPER_DIR/gobind" <<EOF
#!/bin/sh
set -e
if [ -n "\$GOFLAGS" ]; then
    export GOFLAGS="\$GOFLAGS -trimpath"
else
    export GOFLAGS="-trimpath"
fi
exec "$REAL_GOBIND" "\$@"
EOF
chmod +x "$WRAPPER_DIR/gobind"

# Build AAR
echo "Building AAR..."
cd "$GO_SRC_DIR"

# gomobile uses ANDROID_NDK_HOME environment variable (already set above)
# Always use API level 24 (matches app's minSdk)
PATH="$WRAPPER_DIR:$PATH" gomobile bind -target android/arm64,android/amd64 $USE_ANDROID_API -ldflags="$GOMOBILE_LDFLAGS" -o "$OUTPUT_DIR/picocrypt-mobile.aar" ./mobile

expected_abis="$(printf '%s\n' arm64-v8a x86_64)"
actual_abis="$(
    unzip -Z1 "$OUTPUT_DIR/picocrypt-mobile.aar" \
        | sed -n 's#^jni/\([^/]*\)/libgojni\.so$#\1#p' \
        | LC_ALL=C sort
)"
if [ "$actual_abis" != "$expected_abis" ]; then
    echo "Error: unexpected gomobile AAR ABIs" >&2
    echo "Expected:" >&2
    printf '%s\n' "$expected_abis" >&2
    echo "Actual:" >&2
    printf '%s\n' "$actual_abis" >&2
    exit 1
fi

echo "✓ Build successful!"
echo "  AAR location: $OUTPUT_DIR/picocrypt-mobile.aar"
