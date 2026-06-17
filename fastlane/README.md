# Fastlane metadata (F-Droid / IzzyOnDroid)

Store metadata for the Android app, in the Fastlane/Supply layout that F-Droid and
IzzyOnDroid read. Tracks issue #155.

## Layout

```
fastlane/metadata/android/<locale>/
  title.txt                 # max 30 chars
  short_description.txt      # max 80 chars
  full_description.txt       # max 4000 chars (plain text / Markdown / single-line HTML)
  changelogs/<versionCode>.txt   # max 500 bytes, plain ASCII, one file per release
  images/
    icon.png                 # 48x48 .. 512x512, PNG/JPG
    featureGraphic.png       # 512x250 or 1024x500 (optional)
    phoneScreenshots/        # 1.png, 2.png, ... ; max 2:1 side ratio, PNG/JPG
```

`en-US` is required as the fallback locale. Only `en-US` is populated so far.

The fastlane tree lives at the repository root, where F-Droid and IzzyOnDroid expect it by
default (this repo is a monorepo — the Android app lives in `android/`, desktop sources in
`src/`).

## versionCode

`versionCode` is derived from the repo-root `VERSION` file by the release workflow:
`major*10000 + minor*100 + patch`. The current release is **2.16** → base
versionCode `21600` (`VERSION` is `2.16`).

The release ships **per-ABI APKs** (AGP ABI splits, see `app/build.gradle.kts`): each ABI
gets a distinct versionCode `base*10 + offset` (armeabi-v7a=1, arm64-v8a=2, x86=3,
x86_64=4); the universal APK keeps `base`. fdroiddata mirrors this with
`VercodeOperation: [10*%c+1 .. 10*%c+4]`.

fastlane changelogs are keyed by versionCode. ABI splits produce 5 codes per release — the
universal APK keeps the base code and each ABI gets `base*10 + offset` — so a release ships
one `<versionCode>.txt` per code with identical notes (≤ 500 bytes, ASCII): e.g. 2.16 →
`21600.txt` (universal) plus `216001`–`216004.txt`. IzzyOnDroid reads the fastlane tree from
the tagged commit and serves the prebuilt APK without generating changelogs at build time, so
committing the per-code files is what makes the changelog show there; F-Droid matches the same
files by versionCode. Earlier releases' files are kept as history.

## Status

- [x] `images/icon.png` — 140×140 key logo (within F-Droid's 48–512 px range)
- [x] `images/phoneScreenshots/1.png`, `2.png` — main/encrypt screen (showing the Privacy &
      Security screenshot-protection toggle) + decrypt screen (both ≤ 2:1; `1.png` is
      1220×2420 ≈ 1.98:1, `2.png` ≈ 1.84:1)
- [x] Per-ABI APK splits + per-ABI versionCodes (`app/build.gradle.kts`)
- [x] AI-assistance disclosure — addressed upstream on the GitHub/IzzyOnDroid thread
- [ ] Review `title.txt` / `short_description.txt` / `full_description.txt` — drafts, tune
      wording before submitting
- [ ] More locales (only `en-US` is populated)
