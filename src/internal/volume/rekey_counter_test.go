package volume

import (
	"Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/util"
	"bytes"
	"context"
	"crypto/rand"
	mrand "math/rand"
	"os"
	"path/filepath"
	"testing"
)

// deterministicReader is a seeded, repeatable byte source that pins the volume's
// random salt/nonce/IV so two Encrypt calls produce an identical header. That
// leaves the payload keystream (and thus the rekey offset) as the only thing that
// can differ between the full-read and short-read runs.
type deterministicReader struct{ rng *mrand.Rand }

func newDeterministicReader() *deterministicReader {
	// math/rand/v2's ChaCha8 needs Go 1.22; the test only requires a repeatable
	// stream, not specific bytes, so a seeded v1 source is equivalent here.
	return &deterministicReader{rng: mrand.New(mrand.NewSource(1))}
}

func (d *deterministicReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(d.rng.Uint64())
	}
	return len(p), nil
}

// TestRekeyCounterChunkIndependence checks that the rekey offset is driven by the
// plaintext block count, not by how the underlying reader chunks its reads. The
// counter += util.MiB change is equivalent to counter += int64(n) only because
// io.ReadFull feeds full blocks, so this is a guard against future regressions
// rather than a standalone failing test; byte-compat with existing volumes is
// pinned by TestVerifyFirstRekeyAbove60GiB and the golden vectors.
//
// It lowers crypto.RekeyThreshold so a small synthetic volume crosses several
// rekey boundaries, then encrypts the same plaintext twice: once with full reads
// (identity seam) and once under a short-read seam. The two .pcv files must be
// byte-identical.
func TestRekeyCounterChunkIndependence(t *testing.T) {
	rs := newRSCodecsT(t)
	tmp := t.TempDir()

	// Lower the rekey threshold BEFORE Encrypt: NewCounter copies RekeyThreshold
	// at context construction, so it must be set prior to NewEncryptContext.
	prevThreshold := crypto.RekeyThreshold
	crypto.RekeyThreshold = 4 * int64(util.MiB)
	defer func() { crypto.RekeyThreshold = prevThreshold }()

	plaintext := randomPlaintext(t, 8*1024*1024) // 8 MiB -> crosses the 4 MiB rekey boundary
	inputPath := filepath.Join(tmp, "in.bin")
	if err := os.WriteFile(inputPath, plaintext, 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}

	// Pin the volume's random salt/nonce/IV: reset rand.Reader to a freshly
	// seeded deterministic source before each Encrypt so both volumes share an
	// identical header. With identical key/nonce/IV and plaintext, the only thing
	// that can differ between the two .pcv files is the payload keystream, i.e.
	// whether the rekey offset depends on read chunking. Single-file, no-compress
	// encryption draws randomness solely via crypto.RandomBytes.
	prevRand := rand.Reader
	defer func() { rand.Reader = prevRand }()

	encrypt := func(out string) {
		rand.Reader = newDeterministicReader()
		req := &EncryptRequest{
			InputFile:   inputPath,
			OutputFile:  out,
			Password:    []byte("rekey-counter-lock"),
			ReedSolomon: false,
			Reporter:    &GoldenTestReporter{},
			RSCodecs:    rs,
		}
		if err := Encrypt(context.Background(), req); err != nil {
			t.Fatalf("Encrypt(%s): %v", out, err)
		}
	}

	fullPath := filepath.Join(tmp, "full.pcv")
	encrypt(fullPath) // identity seam (full reads)

	// defer the restore so a t.Fatalf inside encrypt() can't leave the seam
	// installed for the rest of the package's volume tests.
	restore := shortReadSeam(shortReadMax)
	defer restore()
	shortPath := filepath.Join(tmp, "short.pcv")
	encrypt(shortPath) // short reads

	full, err := os.ReadFile(fullPath)
	if err != nil {
		t.Fatalf("read full volume: %v", err)
	}
	short, err := os.ReadFile(shortPath)
	if err != nil {
		t.Fatalf("read short volume: %v", err)
	}

	if !bytes.Equal(full, short) {
		t.Fatalf("rekey offset is not chunk-independent: full-read and short-read .pcv differ (len full=%d short=%d)", len(full), len(short))
	}
}
