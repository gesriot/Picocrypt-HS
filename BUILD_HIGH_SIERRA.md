# Building for macOS High Sierra

This fork targets Intel macOS 10.13 High Sierra. Build on the 10.13 machine
with Xcode 9 / SDK 10.13 and **Go 1.20.x** — Go 1.21 and later require macOS
10.15, so 1.20 is the newest toolchain that runs here.

```bash
./build-high-sierra.sh          # GUI + CLI (default)
./build-high-sierra.sh cli      # CLI-only, no Fyne/OpenGL dependencies
```

The script pins `GOTOOLCHAIN=local` so Go never downloads a newer toolchain,
verifies the installed version, and writes `src/Picocrypt-HS`.

Equivalent manual invocation:

```bash
cd src
GOTOOLCHAIN=local CGO_ENABLED=1 \
  MACOSX_DEPLOYMENT_TARGET=10.13 \
  CGO_CFLAGS="-mmacosx-version-min=10.13" \
  CGO_LDFLAGS="-mmacosx-version-min=10.13" \
  go build -tags legacy -ldflags="-s -w" -o Picocrypt-HS ./cmd/picocrypt
```

## Why `-tags legacy` is mandatory here

`legacy` is a **Fyne** build tag, not a Picocrypt one. It excludes exactly one
file in the whole dependency tree, `fyne/app/app_notlegacy_darwin.go`, whose
entire content is:

```go
#cgo LDFLAGS: -framework Foundation -framework UserNotifications
```

`UserNotifications.framework` first shipped in macOS 10.14, so on a 10.13 SDK a
build without the tag dies at link time with `ld: framework not found
UserNotifications`. Fyne's `app_darwin.m` already guards the corresponding
Objective-C behind `__MAC_OS_X_VERSION_MAX_ALLOWED >= 101400` and falls back to
the pre-10.14 notification path, so dropping the framework costs nothing — and
Picocrypt never sends notifications anyway.

The tag is *required* on a 10.13 SDK and *breaks* on a 10.14+ SDK, where
`app_darwin.m` compiles the UserNotifications path and then needs the framework
(the link fails on `_OBJC_CLASS_$_UNUserNotificationCenter`). That asymmetry
means a GUI build of this fork cannot be validated on a modern macOS host; only
the `cli` variant links on both.

## How this fork differs from upstream

Upstream builds with Go 1.26. Keeping it compiling under Go 1.20 requires:

- `src/go.mod` pins `go 1.20` and holds dependencies at their last
  Go 1.20-compatible releases (Fyne 2.7.3, go-i18n 2.5.1, x/crypto 0.33.0 …).
- `crypto/sha3` (stdlib in Go 1.24+) → `golang.org/x/crypto/sha3`.
- `slices` (stdlib in Go 1.21+) → `golang.org/x/exp/slices`.
- `os.Root` (Go 1.24+) → the `openat`-based shim in
  `src/internal/fileops/root_unix.go`, preserving the same confinement
  guarantee for archive extraction.
- `errors.AsType` (Go 1.26) → `errors.As`.
- Builtin `min`, and `for i := range N` loops → Go 1.20 equivalents.
- `github.com/Picocrypt-NG/serpent` is vendored under `src/third_party/serpent`
  because the published module declares `go 1.26.0`; the sources are unmodified.
- `src/internal/ui/lifecycle_test.go` is gated behind `//go:build go1.25`; it
  depends on `testing/synctest`, which has no Go 1.20 equivalent.
