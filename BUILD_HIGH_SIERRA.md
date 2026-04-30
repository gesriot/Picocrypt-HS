# Building for macOS High Sierra

This fork targets Intel macOS 10.13 High Sierra.

Build on macOS 10.13 with Xcode 9 / SDK 10.13:

```bash
cd src
GOTOOLCHAIN=local CGO_ENABLED=1 \
  MACOSX_DEPLOYMENT_TARGET=10.13 \
  CGO_CFLAGS="-mmacosx-version-min=10.13" \
  CGO_LDFLAGS="-mmacosx-version-min=10.13" \
  go build -tags legacy -ldflags="-s -w" -o Picocrypt-HS ./cmd/picocrypt
