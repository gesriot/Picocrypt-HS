#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 4 ]]; then
    echo "Usage: $0 <unsigned-apk-directory> <version-name> <base-version-code> <application-id>" >&2
    exit 2
fi

source_dir=$1
version_name=$2
base_version_code=$3
application_id=$4
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
verifier="$script_dir/verify-release-apks.sh"
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT
if [[ -z "${AAPT:-}" ]]; then
    : "${ANDROID_HOME:?Set AAPT or ANDROID_HOME to locate aapt}"
    AAPT="$ANDROID_HOME/build-tools/36.0.0/aapt"
fi
if [[ -z "${APKSIGNER:-}" ]]; then
    : "${ANDROID_HOME:?Set APKSIGNER or ANDROID_HOME to locate apksigner}"
    APKSIGNER="$ANDROID_HOME/build-tools/36.0.0/apksigner"
fi

copy_unsigned_set() {
    local destination=$1
    mkdir -p "$destination"
    cp "$source_dir"/*-release-unsigned.apk "$destination/"
}

expect_rejected() {
    local description=$1
    local expected_output=$2
    local output
    shift 2

    if output=$("$@" 2>&1); then
        echo "Verifier accepted $description." >&2
        exit 1
    fi
    if [[ "$output" != *"$expected_output"* ]]; then
        echo "Verifier rejected $description for an unexpected reason." >&2
        printf '%s\n' "$output" >&2
        exit 1
    fi
    echo "Release APK verifier rejected $description."
}

replace_manifest_text() {
    local apk=$1
    local old_text=$2
    local new_text=$3
    local edit_dir="$work_dir/manifest-edit"

    if [[ ${#old_text} -ne ${#new_text} ]]; then
        echo "Manifest replacement must preserve string length: '$old_text' -> '$new_text'" >&2
        exit 2
    fi
    rm -rf "$edit_dir"
    mkdir -p "$edit_dir"
    unzip -p "$apk" AndroidManifest.xml > "$edit_dir/AndroidManifest.xml"
    OLD_TEXT=$old_text NEW_TEXT=$new_text perl -0777pi -e '
        BEGIN {
            $old = join("", map { "$_\0" } split(//, $ENV{OLD_TEXT}));
            $new = join("", map { "$_\0" } split(//, $ENV{NEW_TEXT}));
        }
        s/\Q$old\E/$new/g;
    ' "$edit_dir/AndroidManifest.xml"
    (cd "$edit_dir" && zip -q "$apk" AndroidManifest.xml)
}

replace_manifest_version_code() {
    local apk=$1
    local old_code=$2
    local new_code=$3
    local edit_dir="$work_dir/manifest-version-code-edit"

    rm -rf "$edit_dir"
    mkdir -p "$edit_dir"
    unzip -p "$apk" AndroidManifest.xml > "$edit_dir/AndroidManifest.xml"
    OLD_CODE=$old_code NEW_CODE=$new_code perl -0777pi -e '
        BEGIN {
            $old = pack("V", $ENV{OLD_CODE});
            $new = pack("V", $ENV{NEW_CODE});
        }
        s/\Q$old\E/$new/ or die "versionCode value not found\n";
    ' "$edit_dir/AndroidManifest.xml"
    (cd "$edit_dir" && zip -q "$apk" AndroidManifest.xml)
}

"$verifier" "$source_dir" "$version_name" "$base_version_code" "$application_id" unsigned >/dev/null

expect_rejected \
    "a broken aapt executable" \
    "aapt health check failed" \
    env AAPT=/bin/false "$verifier" "$source_dir" "$version_name" "$base_version_code" "$application_id" unsigned
expect_rejected \
    "a broken apksigner executable" \
    "apksigner health check failed" \
    env APKSIGNER=/bin/false "$verifier" "$source_dir" "$version_name" "$base_version_code" "$application_id" unsigned

malformed_aapt="$work_dir/aapt-malformed-version-code"
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    ': "${REAL_AAPT:?Set REAL_AAPT}"' \
    'if [[ ${1:-} == version ]]; then' \
    '    exec "$REAL_AAPT" "$@"' \
    'fi' \
    '"$REAL_AAPT" "$@" | sed "1s/versionCode='\''[^'\'']*'\''/versionCode='\''not-a-number'\''/"' \
    > "$malformed_aapt"
chmod +x "$malformed_aapt"
expect_rejected \
    "malformed numeric metadata" \
    "versionCode metadata is not a decimal integer" \
    env REAL_AAPT="$AAPT" AAPT="$malformed_aapt" \
    "$verifier" "$source_dir" "$version_name" "$base_version_code" "$application_id" unsigned

extra_apk_dir="$work_dir/extra-apk"
copy_unsigned_set "$extra_apk_dir"
cp "$extra_apk_dir/app-universal-release-unsigned.apk" "$extra_apk_dir/unexpected.apk"
expect_rejected \
    "an extra APK" \
    "Release APK set does not match" \
    "$verifier" "$extra_apk_dir" "$version_name" "$base_version_code" "$application_id" unsigned

extra_abi_dir="$work_dir/extra-abi"
copy_unsigned_set "$extra_abi_dir"
extra_abi_payload="$work_dir/extra-abi-payload"
mkdir -p "$extra_abi_payload/lib/armeabi-v7a"
unzip -p \
    "$extra_abi_dir/app-universal-release-unsigned.apk" \
    lib/arm64-v8a/libgojni.so \
    > "$extra_abi_payload/lib/armeabi-v7a/libgojni.so"
(cd "$extra_abi_payload" && zip -q "$extra_abi_dir/app-universal-release-unsigned.apk" lib/armeabi-v7a/libgojni.so)
expect_rejected \
    "an extra native ABI" \
    "native ABI set does not match" \
    "$verifier" "$extra_abi_dir" "$version_name" "$base_version_code" "$application_id" unsigned

missing_gojni_dir="$work_dir/missing-libgojni"
copy_unsigned_set "$missing_gojni_dir"
zip -q -d \
    "$missing_gojni_dir/app-arm64-v8a-release-unsigned.apk" \
    lib/arm64-v8a/libgojni.so
expect_rejected \
    "an APK missing libgojni" \
    "is missing lib/arm64-v8a/libgojni.so" \
    "$verifier" "$missing_gojni_dir" "$version_name" "$base_version_code" "$application_id" unsigned

if [[ ${version_name: -1} == x ]]; then
    wrong_version_name=${version_name%?}y
else
    wrong_version_name=${version_name%?}x
fi
wrong_version_dir="$work_dir/wrong-version-name"
copy_unsigned_set "$wrong_version_dir"
replace_manifest_text \
    "$wrong_version_dir/app-universal-release-unsigned.apk" \
    "$version_name" \
    "$wrong_version_name"
mutated_version_name="$("$AAPT" dump badging "$wrong_version_dir/app-universal-release-unsigned.apk" | sed -n "s/^package: .* versionName='\([^']*\)'.*/\1/p")"
if [[ "$mutated_version_name" != "$wrong_version_name" ]]; then
    echo "Failed to mutate APK versionName: got '$mutated_version_name', want '$wrong_version_name'" >&2
    exit 1
fi
expect_rejected \
    "a wrong versionName" \
    "versionName = '$wrong_version_name'" \
    "$verifier" "$wrong_version_dir" "$version_name" "$base_version_code" "$application_id" unsigned

wrong_base_version_code=$((10#$base_version_code + 1))
wrong_base_dir="$work_dir/wrong-base-version-code"
copy_unsigned_set "$wrong_base_dir"
replace_manifest_version_code \
    "$wrong_base_dir/app-universal-release-unsigned.apk" \
    "$base_version_code" \
    "$wrong_base_version_code"
mutated_base_version_code="$("$AAPT" dump badging "$wrong_base_dir/app-universal-release-unsigned.apk" | sed -n "s/^package: .* versionCode='\([^']*\)'.*/\1/p")"
if [[ "$mutated_base_version_code" != "$wrong_base_version_code" ]]; then
    echo "Failed to mutate APK base versionCode: got '$mutated_base_version_code', want '$wrong_base_version_code'" >&2
    exit 1
fi
expect_rejected \
    "a wrong base versionCode" \
    "versionCode = '$wrong_base_version_code'" \
    "$verifier" "$wrong_base_dir" "$version_name" "$base_version_code" "$application_id" unsigned

signed_names_dir="$work_dir/unsigned-renamed-as-signed"
mkdir -p "$signed_names_dir"
for source in "$source_dir"/*-release-unsigned.apk; do
    filename=${source##*/}
    cp "$source" "$signed_names_dir/${filename/-unsigned/}"
done

expect_rejected \
    "unsigned APKs renamed as signed" \
    "does not have a valid APK signature" \
    "$verifier" "$signed_names_dir" "$version_name" "$base_version_code" "$application_id" signed

keystore="$work_dir/verifier-test.p12"
keytool \
    -genkeypair \
    -keystore "$keystore" \
    -storetype PKCS12 \
    -storepass verifier-test \
    -keypass verifier-test \
    -alias verifier-test \
    -keyalg RSA \
    -keysize 2048 \
    -validity 1 \
    -dname "CN=Picocrypt NG verifier test" \
    -noprompt >/dev/null 2>&1

valid_signed_contents_dir="$work_dir/valid-signed-with-unsigned-names"
copy_unsigned_set "$valid_signed_contents_dir"
for apk in "$valid_signed_contents_dir"/*.apk; do
    "$APKSIGNER" sign \
        --ks "$keystore" \
        --ks-pass pass:verifier-test \
        --key-pass pass:verifier-test \
        --ks-key-alias verifier-test \
        "$apk" >/dev/null 2>&1
done

expect_rejected \
    "validly signed APKs in unsigned mode" \
    "has a valid APK signature, want unsigned" \
    "$verifier" "$valid_signed_contents_dir" "$version_name" "$base_version_code" "$application_id" unsigned

valid_signed_dir="$work_dir/valid-signed"
mkdir -p "$valid_signed_dir"
for source in "$valid_signed_contents_dir"/*-release-unsigned.apk; do
    filename=${source##*/}
    cp "$source" "$valid_signed_dir/${filename/-unsigned/}"
done
"$verifier" "$valid_signed_dir" "$version_name" "$base_version_code" "$application_id" signed >/dev/null
echo "Release APK verifier accepted the same real APKs with valid signatures in signed mode."

wrong_application_id=${application_id%?}x
wrong_application_dir="$work_dir/wrong-application-id"
copy_unsigned_set "$wrong_application_dir"
replace_manifest_text \
    "$wrong_application_dir/app-universal-release-unsigned.apk" \
    "$application_id" \
    "$wrong_application_id"
mutated_application_id="$("$AAPT" dump badging "$wrong_application_dir/app-universal-release-unsigned.apk" | sed -n "s/^package: name='\([^']*\)'.*/\1/p")"
if [[ "$mutated_application_id" != "$wrong_application_id" ]]; then
    echo "Failed to mutate APK application ID: got '$mutated_application_id', want '$wrong_application_id'" >&2
    exit 1
fi

expect_rejected \
    "a wrong application ID" \
    "application ID = '$wrong_application_id'" \
    "$verifier" "$wrong_application_dir" "$version_name" "$base_version_code" "$application_id" unsigned
