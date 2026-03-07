#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "Usage: $0 <mach-o-binary> <max_minos>" >&2
  exit 2
fi

binary="$1"
max_minos="$2"

if command -v llvm-otool >/dev/null 2>&1; then
  otool_bin="llvm-otool"
elif command -v otool >/dev/null 2>&1; then
  otool_bin="otool"
else
  echo "Neither llvm-otool nor otool is available" >&2
  exit 2
fi

if [ ! -f "$binary" ]; then
  echo "Binary not found: $binary" >&2
  exit 2
fi

if ! otool_output="$("$otool_bin" -l "$binary" 2>&1)"; then
  echo "Failed to inspect Mach-O load commands: $otool_bin -l $binary" >&2
  printf '%s\n' "$otool_output" >&2
  exit 2
fi

minos="$(printf '%s\n' "$otool_output" | awk '
function normalize(version, out, i, n, parts) {
  n = split(version, parts, ".")
  for (i = 1; i <= 3; i++) {
    out[i] = (i <= n && parts[i] != "") ? parts[i] + 0 : 0
  }
}
function compare(a, b, va, vb, i) {
  normalize(a, va)
  normalize(b, vb)
  for (i = 1; i <= 3; i++) {
    if (va[i] < vb[i]) return -1
    if (va[i] > vb[i]) return 1
  }
  return 0
}
$1=="minos" {
  if (!found || compare($2, highest) > 0) {
    highest = $2
    found = 1
  }
}
END {
  if (found) print highest
}
')"
if [ -z "$minos" ]; then
  echo "Could not extract minos from: $binary" >&2
  exit 2
fi

if ! awk -v minos="$minos" -v max="$max_minos" '
function normalize(version, out, i, n, parts) {
  n = split(version, parts, ".")
  for (i = 1; i <= 3; i++) {
    out[i] = (i <= n && parts[i] != "") ? parts[i] + 0 : 0
  }
}
BEGIN {
  normalize(minos, current)
  normalize(max, allowed)
  for (i = 1; i <= 3; i++) {
    if (current[i] < allowed[i]) exit 0
    if (current[i] > allowed[i]) exit 1
  }
  exit 0
}
'; then
  echo "FAIL: $binary minos=$minos exceeds allowed max=$max_minos" >&2
  exit 1
fi

echo "PASS: $binary minos=$minos (<= $max_minos)"
