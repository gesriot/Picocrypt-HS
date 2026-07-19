# Vendored github.com/Picocrypt-NG/serpent

Byte-identical copy of `github.com/Picocrypt-NG/serpent v0.1.0`, vendored solely
because the upstream module declares `go 1.26.0` in its `go.mod`, which the Go
1.20 toolchain (the last release supporting macOS 10.13) refuses to compile.
The Go sources are unmodified; only the `go` directive differs.

Wired up via the `replace` directive in `../../go.mod`. When updating this fork
from upstream, re-copy the sources from the matching upstream tag and keep the
`go 1.20` directive.
