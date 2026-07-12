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

flip_apk_byte() {
    local apk=$1
    local offset=$2
    local size

    size=$(stat -c%s "$apk")
    if (( size <= offset )); then
        echo "Cannot flip byte $offset in $apk: file size is $size." >&2
        exit 2
    fi
    OFFSET=$offset perl -e '
        open(my $file, "+<", $ARGV[0]) or die "$ARGV[0]: $!\n";
        binmode $file;
        seek($file, $ENV{OFFSET}, 0) or die "seek: $!\n";
        read($file, my $byte, 1) == 1 or die "read byte\n";
        seek($file, $ENV{OFFSET}, 0) or die "seek: $!\n";
        print {$file} chr(ord($byte) ^ 1) or die "write byte: $!\n";
    ' "$apk"
}

require_apksigner_rejection() {
    local apk=$1
    local description=$2
    local output expected
    shift 2

    if output=$("$APKSIGNER" verify --Werr --verbose --print-certs "$apk" 2>&1); then
        echo "Failed to create $description: apksigner still accepted the APK." >&2
        exit 1
    fi
    for expected in "$@"; do
        if [[ "$output" != *"$expected"* ]]; then
            echo "Failed to create $description: apksigner output lacks '$expected'." >&2
            printf '%s\n' "$output" >&2
            exit 1
        fi
    done
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
expect_rejected \
    "an apksigner executable that returns success without output" \
    "apksigner health check failed" \
    env APKSIGNER=/bin/true "$verifier" "$source_dir" "$version_name" "$base_version_code" "$application_id" unsigned
expect_rejected \
    "a broken readelf executable" \
    "readelf health check failed" \
    env READELF=/bin/false "$verifier" "$source_dir" "$version_name" "$base_version_code" "$application_id" unsigned

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

zero_gojni_dir="$work_dir/zero-byte-libgojni"
copy_unsigned_set "$zero_gojni_dir"
zero_gojni_payload="$work_dir/zero-byte-libgojni-payload"
mkdir -p "$zero_gojni_payload/lib/arm64-v8a"
: > "$zero_gojni_payload/lib/arm64-v8a/libgojni.so"
(cd "$zero_gojni_payload" && zip -q "$zero_gojni_dir/app-arm64-v8a-release-unsigned.apk" lib/arm64-v8a/libgojni.so)
zero_gojni_size=$(unzip -l "$zero_gojni_dir/app-arm64-v8a-release-unsigned.apk" \
    | awk '$4 == "lib/arm64-v8a/libgojni.so" { print $1 }')
if [[ "$zero_gojni_size" != 0 ]]; then
    echo "Failed to replace ARM64 libgojni.so with a zero-byte entry: size '$zero_gojni_size'." >&2
    exit 1
fi
expect_rejected \
    "a zero-byte libgojni" \
    "lib/arm64-v8a/libgojni.so is empty" \
    "$verifier" "$zero_gojni_dir" "$version_name" "$base_version_code" "$application_id" unsigned

wrong_machine_dir="$work_dir/wrong-libgojni-machine"
copy_unsigned_set "$wrong_machine_dir"
wrong_machine_payload="$work_dir/wrong-libgojni-machine-payload"
mkdir -p "$wrong_machine_payload/lib/arm64-v8a"
unzip -p \
    "$source_dir/app-x86_64-release-unsigned.apk" \
    lib/x86_64/libgojni.so \
    > "$wrong_machine_payload/lib/arm64-v8a/libgojni.so"
wrong_machine_header=$(LC_ALL=C readelf -hW "$wrong_machine_payload/lib/arm64-v8a/libgojni.so")
if ! grep -Eq '^[[:space:]]*Machine:[[:space:]]+Advanced Micro Devices X86-64$' <<< "$wrong_machine_header"; then
    echo "Source x86_64 libgojni.so does not report the expected ELF machine." >&2
    exit 1
fi
(cd "$wrong_machine_payload" && zip -q "$wrong_machine_dir/app-arm64-v8a-release-unsigned.apk" lib/arm64-v8a/libgojni.so)
mutated_machine_digest=$(unzip -p \
    "$wrong_machine_dir/app-arm64-v8a-release-unsigned.apk" \
    lib/arm64-v8a/libgojni.so \
    | sha256sum | cut -d' ' -f1)
source_machine_digest=$(sha256sum "$wrong_machine_payload/lib/arm64-v8a/libgojni.so" | cut -d' ' -f1)
if [[ "$mutated_machine_digest" != "$source_machine_digest" ]]; then
    echo "Failed to place the x86_64 libgojni.so in the ARM64 APK." >&2
    exit 1
fi
expect_rejected \
    "an x86_64 libgojni stored in the ARM64 ABI path" \
    "Machine = 'Advanced Micro Devices X86-64', want 'AArch64'" \
    "$verifier" "$wrong_machine_dir" "$version_name" "$base_version_code" "$application_id" unsigned

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

wrong_base_dir="$work_dir/wrong-base-version-code"
copy_unsigned_set "$wrong_base_dir"
wrong_base_version_code="$("$AAPT" dump badging "$wrong_base_dir/app-arm64-v8a-release-unsigned.apk" | sed -n "s/^package: .* versionCode='\([^']*\)'.*/\1/p")"
if [[ ! "$wrong_base_version_code" =~ ^[0-9]+$ ]]; then
    echo "ARM64 APK versionCode is not a decimal integer: '$wrong_base_version_code'" >&2
    exit 1
fi
if (( 10#$wrong_base_version_code == 10#$base_version_code )); then
    echo "ARM64 APK versionCode must differ from the base versionCode" >&2
    exit 1
fi
wrong_base_manifest_dir="$work_dir/wrong-base-version-code-manifest"
mkdir -p "$wrong_base_manifest_dir"
unzip -p \
    "$wrong_base_dir/app-arm64-v8a-release-unsigned.apk" \
    AndroidManifest.xml \
    > "$wrong_base_manifest_dir/AndroidManifest.xml"
(cd "$wrong_base_manifest_dir" && zip -q "$wrong_base_dir/app-universal-release-unsigned.apk" AndroidManifest.xml)
mutated_base_version_code="$("$AAPT" dump badging "$wrong_base_dir/app-universal-release-unsigned.apk" | sed -n "s/^package: .* versionCode='\([^']*\)'.*/\1/p")"
if [[ "$mutated_base_version_code" != "$wrong_base_version_code" ]]; then
    echo "Failed to mutate APK base versionCode: got '$mutated_base_version_code', want '$wrong_base_version_code'" >&2
    exit 1
fi
expect_rejected \
    "a wrong base versionCode" \
    "versionCode = '$wrong_base_version_code'" \
    "$verifier" "$wrong_base_dir" "$version_name" "$base_version_code" "$application_id" unsigned

wrong_signer_digest_file="$work_dir/wrong-signer-sha256.txt"
printf '%064d\n' 0 > "$wrong_signer_digest_file"

signed_names_dir="$work_dir/unsigned-renamed-as-signed"
mkdir -p "$signed_names_dir"
for source in "$source_dir"/*-release-unsigned.apk; do
    filename=${source##*/}
    cp "$source" "$signed_names_dir/${filename/-unsigned/}"
done

expect_rejected \
    "unsigned APKs renamed as signed" \
    "does not have a valid APK signature" \
    env PICOCRYPT_ANDROID_SIGNING_CERT_SHA256_FILE="$wrong_signer_digest_file" \
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

stripped_signature_dir="$work_dir/stripped-signature-with-unsigned-names"
cp -a "$valid_signed_contents_dir" "$stripped_signature_dir"
stripped_payload="$work_dir/stripped-signature-payload"
mkdir -p "$stripped_payload/lib/arm64-v8a"
unzip -p \
    "$stripped_signature_dir/app-arm64-v8a-release-unsigned.apk" \
    lib/arm64-v8a/libgojni.so \
    > "$stripped_payload/lib/arm64-v8a/libgojni.so"
original_stripped_size=$(stat -c%s "$stripped_payload/lib/arm64-v8a/libgojni.so")
printf X >> "$stripped_payload/lib/arm64-v8a/libgojni.so"
(cd "$stripped_payload" && zip -q "$stripped_signature_dir/app-arm64-v8a-release-unsigned.apk" lib/arm64-v8a/libgojni.so)
mutated_stripped_size=$(unzip -p \
    "$stripped_signature_dir/app-arm64-v8a-release-unsigned.apk" \
    lib/arm64-v8a/libgojni.so \
    | wc -c)
if (( mutated_stripped_size != original_stripped_size + 1 )); then
    echo "Failed to update the signed APK before checking stripped-signature handling." >&2
    exit 1
fi
require_apksigner_rejection \
    "$stripped_signature_dir/app-arm64-v8a-release-unsigned.apk" \
    "an APK with stripped signature metadata" \
    "Signature stripped?"
expect_rejected \
    "an APK with a recognizably stripped signature in unsigned mode" \
    "does not match the pinned genuine-unsigned diagnostic" \
    "$verifier" "$stripped_signature_dir" "$version_name" "$base_version_code" "$application_id" unsigned

integrity_mismatch_dir="$work_dir/integrity-mismatch-with-unsigned-names"
cp -a "$valid_signed_contents_dir" "$integrity_mismatch_dir"
flip_apk_byte "$integrity_mismatch_dir/app-arm64-v8a-release-unsigned.apk" 4096
require_apksigner_rejection \
    "$integrity_mismatch_dir/app-arm64-v8a-release-unsigned.apk" \
    "an APK with a signature-protected byte changed" \
    "APK integrity check failed" \
    "digest mismatch"
expect_rejected \
    "an APK with a signature integrity mismatch in unsigned mode" \
    "does not match the pinned genuine-unsigned diagnostic" \
    "$verifier" "$integrity_mismatch_dir" "$version_name" "$base_version_code" "$application_id" unsigned

valid_signed_dir="$work_dir/valid-signed"
mkdir -p "$valid_signed_dir"
for source in "$valid_signed_contents_dir"/*-release-unsigned.apk; do
    filename=${source##*/}
    cp "$source" "$valid_signed_dir/${filename/-unsigned/}"
done

test_signer_digest_file="$work_dir/test-signer-sha256.txt"
"$APKSIGNER" verify --Werr --verbose --print-certs \
    "$valid_signed_dir/app-arm64-v8a-release.apk" \
    | sed -n 's/^Signer #1 certificate SHA-256 digest: //p' \
    > "$test_signer_digest_file"
if [[ ! "$(< "$test_signer_digest_file")" =~ ^[0-9a-f]{64}$ ]]; then
    echo "Failed to capture the temporary test signer SHA-256 digest." >&2
    exit 1
fi
if [[ "$(< "$test_signer_digest_file")" == "$(< "$wrong_signer_digest_file")" ]]; then
    echo "Temporary test signer unexpectedly matches the deliberately wrong digest." >&2
    exit 1
fi
expect_rejected \
    "APKs signed by an untrusted certificate" \
    "signer certificate SHA-256" \
    env PICOCRYPT_ANDROID_SIGNING_CERT_SHA256_FILE="$wrong_signer_digest_file" \
    "$verifier" "$valid_signed_dir" "$version_name" "$base_version_code" "$application_id" signed

env PICOCRYPT_ANDROID_SIGNING_CERT_SHA256_FILE="$test_signer_digest_file" \
    "$verifier" "$valid_signed_dir" "$version_name" "$base_version_code" "$application_id" signed >/dev/null
echo "Release APK verifier accepted the same real APKs with valid signatures in signed mode."

signed_tampered_dir="$work_dir/signed-tampered"
cp -a "$valid_signed_dir" "$signed_tampered_dir"
flip_apk_byte "$signed_tampered_dir/app-arm64-v8a-release.apk" 4096
require_apksigner_rejection \
    "$signed_tampered_dir/app-arm64-v8a-release.apk" \
    "a tampered signed APK" \
    "APK integrity check failed" \
    "digest mismatch"
expect_rejected \
    "a tampered APK in signed mode" \
    "does not have a valid APK signature" \
    env PICOCRYPT_ANDROID_SIGNING_CERT_SHA256_FILE="$test_signer_digest_file" \
    "$verifier" "$signed_tampered_dir" "$version_name" "$base_version_code" "$application_id" signed

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
