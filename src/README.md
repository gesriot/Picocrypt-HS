# Building from Source

## Prerequisites

**Linux:**
```bash
apt install -y gcc xorg-dev libgtk-3-dev libgl1-mesa-dev libglu1-mesa
```

**macOS:**
```bash
xcode-select --install
brew install glfw glew
```

**Windows:** TDM-GCC or MinGW-w64

## Install Go

Download from [go.dev/dl](https://go.dev/dl/) or use your package manager. Go 1.24+ recommended.

## Build

```bash
git clone https://github.com/Picocrypt-NG/Picocrypt-NG.git
cd Picocrypt-NG/src

# Linux/macOS
CGO_ENABLED=1 go build -ldflags="-s -w" -o Picocrypt-NG cmd/picocrypt/main.go

# Windows
CGO_ENABLED=1 go build -ldflags="-s -w -H=windowsgui -extldflags=-static" -o Picocrypt-NG.exe cmd/picocrypt/main.go
```

## Run

```bash
./Picocrypt-NG
```

## Android

The Android build path now lives in the repository root `android/` project and uses gomobile bindings from `src/mobile/`. See `../android/README.md` for the native Android app build instructions.

## Test

```bash
# Fast default local suite
go test ./...

# Golden compatibility checks with production KDF
go test -run 'TestGoldenDecryption|TestGoldenCompressedDecryption|TestGoldenWrongPassword|TestGoldenV1WrongPassword' ./internal/volume

# Opt-in CLI integration tests
PICOCRYPT_RUN_CLI_INTEGRATION=1 go test ./internal/cli
```

## Notes

- On Linux without hardware OpenGL: `LIBGL_ALWAYS_SOFTWARE=1 ./Picocrypt-NG`
- If accessibility bus causes issues: `NO_AT_BRIDGE=1 ./Picocrypt-NG`
