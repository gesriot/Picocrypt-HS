//go:build race

package mobile

// raceEnabled reports whether the test binary was built with -race.
// True under `go test -race`; lets us skip the one mobile test that drives the
// real, memory-hard (~1 GiB) Argon2id KDF. Under the race detector's shadow
// memory, times `go test ./...` package parallelism, that allocation exhausts
// the hosted amd64 CI runner (SIGTERM / exit 143). The KDF exercises crypto,
// not concurrency, so -race adds no coverage there; the same test still runs on
// the no-race matrix (arm64) and locally.
const raceEnabled = true
