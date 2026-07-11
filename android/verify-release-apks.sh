#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 4 ]]; then
    echo "Usage: $0 <apk-directory> <version-name> <base-version-code> <unsigned|signed>" >&2
    exit 2
fi

apk_dir=$1
expected_version_name=$2
base_version_code=$3
build_kind=$4

if [[ ! -d "$apk_dir" ]]; then
    echo "APK directory does not exist: $apk_dir" >&2
    exit 1
fi
if [[ -z "$expected_version_name" ]]; then
    echo "Expected versionName must not be empty" >&2
    exit 2
fi
if [[ ! "$base_version_code" =~ ^[0-9]+$ ]]; then
    echo "Base versionCode must be a non-negative integer: $base_version_code" >&2
    exit 2
fi

case "$build_kind" in
    unsigned)
        filename_suffix=-unsigned
        ;;
    signed)
        filename_suffix=
        ;;
    *)
        echo "Build kind must be unsigned or signed: $build_kind" >&2
        exit 2
        ;;
esac

if [[ -z "${AAPT:-}" ]]; then
    : "${ANDROID_HOME:?Set AAPT or ANDROID_HOME to locate aapt}"
    AAPT="$ANDROID_HOME/build-tools/36.0.0/aapt"
fi
if [[ ! -x "$AAPT" ]]; then
    echo "aapt is not executable: $AAPT" >&2
    exit 1
fi

expected_files="$(printf '%s\n' \
    "app-arm64-v8a-release${filename_suffix}.apk" \
    "app-universal-release${filename_suffix}.apk" \
    "app-x86_64-release${filename_suffix}.apk")"
actual_files="$(find "$apk_dir" -maxdepth 1 -type f -name '*.apk' -printf '%f\n' | LC_ALL=C sort)"
if [[ "$actual_files" != "$expected_files" ]]; then
    echo "Release APK set does not match the exact $build_kind contract." >&2
    echo "Expected:" >&2
    printf '%s\n' "$expected_files" >&2
    echo "Actual:" >&2
    printf '%s\n' "${actual_files:-<none>}" >&2
    exit 1
fi

base_version_code=$((10#$base_version_code))

verify_apk() {
    local filename=$1
    local expected_version_code=$2
    local expected_abis=$3
    local apk="$apk_dir/$filename"
    local badging package_line actual_version_code actual_version_name entries actual_abis

    badging="$("$AAPT" dump badging "$apk")"
    package_line=${badging%%$'\n'*}
    actual_version_code="$(sed -n "s/^package: .* versionCode='\([^']*\)'.*/\1/p" <<< "$package_line")"
    actual_version_name="$(sed -n "s/^package: .* versionName='\([^']*\)'.*/\1/p" <<< "$package_line")"

    if [[ "$actual_version_name" != "$expected_version_name" ]]; then
        echo "$filename versionName = '$actual_version_name', want '$expected_version_name'" >&2
        exit 1
    fi
    if [[ "$actual_version_code" != "$expected_version_code" ]]; then
        echo "$filename versionCode = '$actual_version_code', want '$expected_version_code'" >&2
        exit 1
    fi
    if ! grep -Fx "sdkVersion:'24'" <<< "$badging" >/dev/null; then
        echo "$filename does not declare minSdk 24" >&2
        exit 1
    fi

    entries="$(unzip -Z1 "$apk")"
    actual_abis="$(awk -F/ '$1 == "lib" && NF >= 3 { print $2 }' <<< "$entries" | LC_ALL=C sort -u)"
    if [[ "$actual_abis" != "$expected_abis" ]]; then
        echo "$filename native ABI set does not match." >&2
        echo "Expected:" >&2
        printf '%s\n' "$expected_abis" >&2
        echo "Actual:" >&2
        printf '%s\n' "${actual_abis:-<none>}" >&2
        exit 1
    fi
    while IFS= read -r abi; do
        if ! grep -Fx "lib/$abi/libgojni.so" <<< "$entries" >/dev/null; then
            echo "$filename is missing lib/$abi/libgojni.so" >&2
            exit 1
        fi
    done <<< "$expected_abis"
}

verify_apk \
    "app-arm64-v8a-release${filename_suffix}.apk" \
    "$((base_version_code * 10 + 2))" \
    "arm64-v8a"
verify_apk \
    "app-universal-release${filename_suffix}.apk" \
    "$base_version_code" \
    "$(printf '%s\n' arm64-v8a x86_64)"
verify_apk \
    "app-x86_64-release${filename_suffix}.apk" \
    "$((base_version_code * 10 + 4))" \
    "x86_64"

echo "Verified exact $build_kind Android release APK contract for version $expected_version_name (base versionCode $base_version_code)."
