#!/bin/bash
# Package Picocrypt-HS as a .app bundle (with icon) inside a .dmg, for Intel
# macOS 10.13 High Sierra.
#
#   ./build-dmg.sh          # GUI build (what you normally want)
#   ./build-dmg.sh cli      # CLI-only binary in the bundle; for testing the
#                           # packaging itself on a machine that cannot link
#                           # the GUI (see BUILD_HIGH_SIERRA.md)
#
# Produces Picocrypt-HS.app and Picocrypt-HS.dmg in the repository root.

set -euo pipefail

cd "$(dirname "$0")"
ROOT="$(pwd)"

APP_NAME="Picocrypt-HS"
APP="$ROOT/$APP_NAME.app"
DMG="$ROOT/$APP_NAME.dmg"
STAGING="$ROOT/.dmg-staging"
VERSION="$(tr -d '[:space:]' <VERSION)"

# The icon and the canonical Info.plist come from upstream's dist/macos. The
# plist is patched below rather than copied into a fork-specific duplicate, so
# upstream changes to it flow through on the next merge.
ICON_SRC="$ROOT/dist/macos/iconSmall.icns"
PLIST_SRC="$ROOT/dist/macos/Info.plist"

for f in "$ICON_SRC" "$PLIST_SRC"; do
	if [ ! -f "$f" ]; then
		echo "error: missing $f" >&2
		exit 1
	fi
done

./build-high-sierra.sh "$@"

echo
echo "Packaging $APP_NAME.app (version $VERSION)"

rm -rf "$APP" "$STAGING" "$DMG"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

cp "$ROOT/src/Picocrypt-HS" "$APP/Contents/MacOS/$APP_NAME"
chmod +x "$APP/Contents/MacOS/$APP_NAME"
cp "$ICON_SRC" "$APP/Contents/Resources/icon.icns"
cp "$PLIST_SRC" "$APP/Contents/Info.plist"

PLIST="$APP/Contents/Info.plist"
# Rebrand NG -> HS, drop upstream's macOS 15 floor to 10.13, and stamp the
# version from the root VERSION file.
plutil -replace CFBundleIdentifier -string "io.github.picocryptng.PicocryptHS" "$PLIST"
plutil -replace CFBundleName -string "$APP_NAME" "$PLIST"
plutil -replace CFBundleDisplayName -string "$APP_NAME" "$PLIST"
plutil -replace CFBundleExecutable -string "$APP_NAME" "$PLIST"
plutil -replace CFBundleIconFile -string "icon.icns" "$PLIST"
plutil -replace LSMinimumSystemVersion -string "10.13" "$PLIST"
plutil -replace CFBundleShortVersionString -string "$VERSION" "$PLIST"
plutil -replace CFBundleVersion -string "$VERSION" "$PLIST"
plutil -lint "$PLIST"

# Ad-hoc signature. The bundle is assembled by hand, so seal it so 10.13 does
# not treat it as damaged. Not a substitute for a Developer ID signature: the
# first launch still needs right-click -> Open, or a Gatekeeper exemption.
if ! codesign --force --deep --sign - "$APP" 2>/dev/null; then
	echo "warning: ad-hoc codesign failed; the .app should still run via right-click -> Open" >&2
fi

mkdir -p "$STAGING"
cp -R "$APP" "$STAGING/"
ln -s /Applications "$STAGING/Applications"

# HFS+ rather than APFS: readable by every macOS that can run this build.
hdiutil create "$DMG" \
	-volname "$APP_NAME" \
	-fs HFS+ \
	-format UDZO \
	-srcfolder "$STAGING" \
	-quiet

rm -rf "$STAGING"

echo
echo "Built $APP_NAME.app and $APP_NAME.dmg"
ls -lh "$DMG"
