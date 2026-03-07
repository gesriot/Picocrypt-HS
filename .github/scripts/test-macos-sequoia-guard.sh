#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

fail=0

if [ ! -f ".github/scripts/assert-macos-minos.sh" ]; then
  echo "Missing .github/scripts/assert-macos-minos.sh" >&2
  fail=1
fi

for expected in \
  '      - ".github/workflows/build-macos.yml"' \
  '      - ".github/scripts/assert-macos-minos.sh"'
do
  if ! rg -Fq "$expected" ".github/workflows/build-macos.yml"; then
    echo ".github/workflows/build-macos.yml is missing trigger path: $expected" >&2
    fail=1
  fi
done

for workflow in \
  ".github/workflows/build-macos.yml" \
  ".github/workflows/pr-test-build-macos.yml"
do
  for expected in \
    'MACOSX_DEPLOYMENT_TARGET: "15.0"' \
    'CGO_CFLAGS: "-mmacosx-version-min=15.0"' \
    'CGO_LDFLAGS: "-mmacosx-version-min=15.0"' \
    'bash .github/scripts/assert-macos-minos.sh src/Picocrypt-NG 15.0'
  do
    if ! rg -Fq "$expected" "$workflow"; then
      echo "$workflow is missing: $expected" >&2
      fail=1
    fi
  done
done

if [ "$fail" -ne 0 ]; then
  exit 1
fi

echo "PASS: macOS Sequoia guard is present in both workflows"
