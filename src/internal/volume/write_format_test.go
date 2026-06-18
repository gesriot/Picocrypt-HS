package volume

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/header"
)

// TestWriteFormatRegression locks the HEAD write-format against the frozen
// on-disk layout (REL-01, threat T-01-01). It encrypts fixed inputs and asserts
// the written volume decodes to the frozen header field widths and the current
// version constant, then self-decrypts back to the original plaintext.
//
// It deliberately does NOT hash the full encrypt output: encryptGenerateValues
// draws random salt/HKDFSalt/SerpentIV/nonce via crypto.RandomBytes with no
// injection seam, so a full-output hash would be non-deterministic (RESEARCH
// Pitfall 1). The structural-invariant + self-decrypt assertions below are the
// deterministic write-format lock; no RNG seam is added to production crypto.
//
// Assertions are written against the header.*Size constants and
// header.CurrentVersion (the CONSTANT), not string/number literals, so this
// test survives release version-string bumps unchanged while still
// turning RED on any genuine field-width / version / flag-layout drift.
func TestWriteFormatRegression(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "pt.txt")
	if err := os.WriteFile(inputPath, []byte(expectedContent), 0644); err != nil {
		t.Fatalf("Failed to write input file: %v", err)
	}
	outputPath := filepath.Join(tmpDir, "v_out.txt.pcv")

	// Encrypt fixed inputs (basic volume: no paranoid/RS/deniability).
	// Runs under the package-default fast KDF (TestMain) — it self-decrypts.
	encReq := &EncryptRequest{
		InputFile:   inputPath,
		OutputFile:  outputPath,
		Password:    []byte(goldenPassword),
		Paranoid:    false,
		ReedSolomon: false,
		Deniability: false,
		Reporter:    &GoldenTestReporter{},
		RSCodecs:    rsCodecs,
	}
	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read encrypted output: %v", err)
	}

	// (1) Length floor: the written volume is at least a full base header.
	if len(data) < header.BaseHeaderSize {
		t.Fatalf("header truncated: %d < %d (header.BaseHeaderSize)", len(data), header.BaseHeaderSize)
	}

	// Decode the header structurally — reuse the in-package reader, which knows
	// every RS field width. Do NOT hand-roll a byte-offset parser.
	fin, err := os.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open output: %v", err)
	}
	defer func() { _ = fin.Close() }()

	res, err := NewHeaderReaderForTest(fin, rsCodecs).ReadHeader()
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	if res.DecodeError != nil {
		t.Fatalf("header decode error: %v", res.DecodeError)
	}
	h := res.Header

	// (2) Version invariant: assert against the CONSTANT, never a literal.
	if h.Version != header.CurrentVersion {
		t.Errorf("decoded version = %q, want header.CurrentVersion %q", h.Version, header.CurrentVersion)
	}

	// (3) Frozen field widths: every crypto field decodes to its header.*Size.
	if got := len(h.Salt); got != header.SaltSize {
		t.Errorf("Salt width = %d, want header.SaltSize %d", got, header.SaltSize)
	}
	if got := len(h.HKDFSalt); got != header.HKDFSaltSize {
		t.Errorf("HKDFSalt width = %d, want header.HKDFSaltSize %d", got, header.HKDFSaltSize)
	}
	if got := len(h.SerpentIV); got != header.SerpentIVSize {
		t.Errorf("SerpentIV width = %d, want header.SerpentIVSize %d", got, header.SerpentIVSize)
	}
	if got := len(h.Nonce); got != header.NonceSize {
		t.Errorf("Nonce width = %d, want header.NonceSize %d", got, header.NonceSize)
	}
	if got := len(h.KeyfileHash); got != header.KeyfileHashSize {
		t.Errorf("KeyfileHash width = %d, want header.KeyfileHashSize %d", got, header.KeyfileHashSize)
	}
	if got := len(h.KeyHash); got != header.KeyHashSize {
		t.Errorf("KeyHash width = %d, want header.KeyHashSize %d", got, header.KeyHashSize)
	}
	if got := len(h.AuthTag); got != header.AuthTagSize {
		t.Errorf("AuthTag width = %d, want header.AuthTagSize %d", got, header.AuthTagSize)
	}

	// (4) Flags invariant: a basic volume has these all false.
	if h.Flags.Paranoid || h.Flags.UseKeyfiles || h.Flags.ReedSolomon {
		t.Errorf("unexpected flags for basic volume: Paranoid=%v UseKeyfiles=%v ReedSolomon=%v",
			h.Flags.Paranoid, h.Flags.UseKeyfiles, h.Flags.ReedSolomon)
	}

	// (5) Roundtrip: the write-format is valid iff it self-decrypts to plaintext.
	decryptedPath := filepath.Join(tmpDir, "dec.txt")
	decReq := &DecryptRequest{
		InputFile:    outputPath,
		OutputFile:   decryptedPath,
		Password:     []byte(goldenPassword),
		ForceDecrypt: false,
		Reporter:     &GoldenTestReporter{},
		RSCodecs:     rsCodecs,
	}
	if err := Decrypt(context.Background(), decReq); err != nil {
		t.Fatalf("self-decrypt failed: %v", err)
	}

	got, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted output: %v", err)
	}
	if string(got) != expectedContent {
		t.Errorf("roundtrip mismatch.\nExpected: %q\nGot: %q", expectedContent, string(got))
	}
}
