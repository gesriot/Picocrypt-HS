// Package distmeta exposes contract tests for canonical distribution metadata
// (shared-mime-info XML, file-icon assets) shared across platform fases 2-4.
//
// This package is test-only: it has no runtime code. Tests live in
// distmeta_test.go and validate that artefacts under dist/mime/ and
// images/pcv-icon* match the contract expected by Linux MIME, macOS UTI,
// and Windows NSIS packaging steps.
package distmeta
