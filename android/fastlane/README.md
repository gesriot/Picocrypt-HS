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

F-Droid looks for this folder relative to the build's `subdir`; the fdroiddata recipe
must point at `android/fastlane` (this repo is a monorepo — the Android app lives in
`android/`, desktop sources in `src/`).

## versionCode

`versionCode` is derived from the repo-root `VERSION` file by the release workflow:
`major*10000 + minor*100 + patch`. The first F-Droid release targets **2.15** → base
versionCode `21500`. (`VERSION` is still `2.14`; it is bumped when the release is cut.)

The release ships **per-ABI APKs** (AGP ABI splits, see `app/build.gradle.kts`): each ABI
gets a distinct versionCode `base*10 + offset` (armeabi-v7a=1, arm64-v8a=2, x86=3,
x86_64=4); the universal APK keeps `base`. fdroiddata mirrors this with
`VercodeOperation: [10*%c+1 .. 10*%c+4]`.

We keep **one** changelog file per release (`changelogs/<base>.txt`, e.g. `21500.txt`)
and never commit per-ABI mirror files (`215001.txt` …) — they would multiply by four
every release and pollute git history. Consequence: F-Droid/IzzyOnDroid show no
per-version changelog for the per-ABI builds (the store description carries the feature
list). If per-ABI changelogs are ever wanted, the fdroiddata build recipe can generate
them transiently — they must not land in this repo's history.

## Status

- [x] `images/icon.png` — 140×140 key logo (within F-Droid's 48–512 px range)
- [x] `images/phoneScreenshots/1.png`, `2.png` — encrypt + decrypt screens (both ≤ 2:1;
      `1.png` was side-padded from 2.17:1 to 1.99:1 to meet the limit)
- [x] Per-ABI APK splits + per-ABI versionCodes (`app/build.gradle.kts`)
- [x] AI-assistance disclosure — addressed upstream on the GitHub/IzzyOnDroid thread
- [ ] Review `title.txt` / `short_description.txt` / `full_description.txt` — drafts, tune
      wording before submitting
- [ ] More locales (only `en-US` is populated)
