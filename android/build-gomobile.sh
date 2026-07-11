#!/bin/bash
# Build script for Go Mobile bindings
# This script builds the Go mobile AAR library for Android

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GO_SRC_DIR="$SCRIPT_DIR/../src"
OUTPUT_DIR="$SCRIPT_DIR/app/libs"
GOMOBILE_LDFLAGS="${GOMOBILE_LDFLAGS:--s -w -buildid=}"

# Set Android SDK/NDK paths
export ANDROID_HOME="${ANDROID_HOME:-/opt/android-sdk}"
export ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-$ANDROID_HOME}"

# Extract NDK version from path and validate it's 29.0+
# Returns the major version number (e.g., "29" from "29.0.14206865")
get_ndk_major_version() {
    local ndk_path="$1"
    # Extract version from path like /path/to/ndk/29.0.14206865
    local version=$(basename "$ndk_path")
    # Extract major version (first number before first dot)
    echo "${version%%.*}"
}

# Validate NDK version is 29.0 or higher
validate_ndk_version() {
    local ndk_path="$1"
    if [ ! -d "$ndk_path" ]; then
        echo "Error: NDK path does not exist: $ndk_path" >&2
        return 1
    fi
    
    local major_version=$(get_ndk_major_version "$ndk_path")
    if [ -z "$major_version" ] || ! [[ "$major_version" =~ ^[0-9]+$ ]]; then
        echo "Error: Could not determine NDK version from path: $ndk_path" >&2
        return 1
    fi
    
    if [ "$major_version" -lt 29 ]; then
        echo "Error: NDK version $major_version is too old. NDK 29.0 or higher is required." >&2
        echo "  Found NDK at: $ndk_path" >&2
        echo "  Please install NDK 29.0 or higher." >&2
        return 1
    fi
    
    return 0
}

# Find and validate NDK 29+
if [ -n "$ANDROID_NDK_HOME" ] && [ -d "$ANDROID_NDK_HOME" ]; then
    # ANDROID_NDK_HOME is already set (e.g., by GitHub Actions)
    echo "Using NDK from ANDROID_NDK_HOME: $ANDROID_NDK_HOME"
    if ! validate_ndk_version "$ANDROID_NDK_HOME"; then
        exit 1
    fi
elif [ -d "$ANDROID_HOME/ndk" ]; then
    # Find the latest NDK version (should be 29+)
    NDK_VERSION=$(ls -1 "$ANDROID_HOME/ndk" | sort -V | tail -1)
    if [ -n "$NDK_VERSION" ]; then
        export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/$NDK_VERSION"
        echo "Using NDK: $ANDROID_NDK_HOME"
        if ! validate_ndk_version "$ANDROID_NDK_HOME"; then
            exit 1
        fi
    else
        echo "Error: No NDK found in $ANDROID_HOME/ndk" >&2
        exit 1
    fi
elif [ -d "$ANDROID_HOME/ndk-bundle" ]; then
    export ANDROID_NDK_HOME="$ANDROID_HOME/ndk-bundle"
    echo "Using NDK: $ANDROID_NDK_HOME"
    if ! validate_ndk_version "$ANDROID_NDK_HOME"; then
        exit 1
    fi
else
    echo "Error: NDK not found. Please install NDK 29.0 or higher." >&2
    echo "  Expected location: $ANDROID_HOME/ndk" >&2
    exit 1
fi

# Always use API level 24 (matches app's minSdk, required for NDK 29+)
USE_ANDROID_API="-androidapi 24"

echo "Building Go Mobile bindings for Android..."
echo "Go source directory: $GO_SRC_DIR"
echo "Output directory: $OUTPUT_DIR"
echo "Android SDK: $ANDROID_HOME"
echo "Android NDK: ${ANDROID_NDK_HOME:-not set}"
echo "Go linker flags: $GOMOBILE_LDFLAGS"

# Check if gomobile is installed
if ! command -v gomobile &> /dev/null; then
    echo "Error: gomobile not found in PATH." >&2
    echo "  Install it first with: go install golang.org/x/mobile/cmd/gomobile@v0.0.0-20260709172247-6129f5bee9d5" >&2
    echo "  Install gobind too with: go install golang.org/x/mobile/cmd/gobind@v0.0.0-20260709172247-6129f5bee9d5" >&2
    echo "  Then create the gomobile toolchain dir with: mkdir -p \"\$(go env GOPATH | cut -d: -f1)/pkg/gomobile\"" >&2
    exit 1
fi

if ! command -v gobind &> /dev/null; then
    echo "Error: gobind not found in PATH." >&2
    echo "  Install it with: go install golang.org/x/mobile/cmd/gobind@v0.0.0-20260709172247-6129f5bee9d5" >&2
    exit 1
fi

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
# Always use API level 24 (matches app's minSdk, required for NDK 29+)
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
