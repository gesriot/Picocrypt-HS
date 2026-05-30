package volume

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/util"
)

// recordingReporter is a ProgressReporter that records every SetProgress
// fraction (paired with its info string) into a slice. The existing test
// reporters (GoldenTestReporter, repairingReporter) DISCARD the fraction; this
// one keeps it so a test can assert progress monotonicity / no-overshoot.
//
// VER-03: the verify-first pass emits SetProgress(progress/2, "...(verifying)")
// for pass 1 (0..0.5) and SetProgress(progress, "...") for the decrypt pass
// (0..1.0). Filtering on the "(verifying)" marker isolates pass-1 samples.
type recordingReporter struct {
	fractions []float32
	infos     []string
	cancelled bool
}

func (r *recordingReporter) SetStatus(text string) {}

func (r *recordingReporter) SetProgress(fraction float32, info string) {
	r.fractions = append(r.fractions, fraction)
	r.infos = append(r.infos, info)
}

func (r *recordingReporter) SetCanCancel(can bool) {}

func (r *recordingReporter) Update() {}

func (r *recordingReporter) IsCancelled() bool {
	return r.cancelled
}

// pass1Fractions returns the recorded fractions whose info string carries the
// verify pass marker "(verifying)" — i.e. the pass-1 (0..0.5) samples.
func (r *recordingReporter) pass1Fractions() []float32 {
	var out []float32
	for i, info := range r.infos {
		if strings.Contains(info, "(verifying)") {
			out = append(out, r.fractions[i])
		}
	}
	return out
}

// TestVerifyFirstProgressDeltaFaithful is the FALSIFIABLE VER-03 unit test (D-13/D-14,
// mechanism a). It pins the verify-first pass's per-read progress increment to the
// ACTUAL bytes read, matching how ctx.Total is computed (raw on-disk ciphertext byte
// count: filesize - headerSize - comments*3, decrypt.go:160,192).
//
// Why a dedicated unit test (Rule 9 — encode WHY, must fail when logic is wrong):
// the buggy code increments `done` by a FIXED full-block size
// (util.MiB/RS128DataSize*RS128EncodedSize = 1,114,112) per read regardless of the
// actual bytes read `n`. On the final partial read (n < that block size) this pushes
// `done` past ctx.Total. The integration-level reporter assertion below CANNOT catch
// this because util.Statify already clamps the reported fraction to <=1.0 — so the
// over-count is masked at the display layer. This unit test observes the increment
// BEFORE the clamp, so it fails RED against the fixed-block bug and passes only once
// the increment is `int64(n)` (faithful to ctx.Total's raw-byte basis).
func TestVerifyFirstProgressDeltaFaithful(t *testing.T) {
	const fixedBlock = int64(util.MiB / encoding.RS128DataSize * encoding.RS128EncodedSize)

	tests := []struct {
		name string
		n    int
		want int64
	}{
		{
			name: "rs partial final read advances by actual bytes, not fixed block",
			n:    12345, // a short final read: n << fixedBlock; pre-fix advanced by fixedBlock
			want: 12345, // faithful: matches the on-disk bytes counted in ctx.Total
		},
		{
			name: "full read advances by the bytes read (== fixed block at a full chunk)",
			n:    int(fixedBlock),
			want: fixedBlock,
		},
		{
			name: "small read advances by actual bytes",
			n:    9001,
			want: 9001,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := verifyFirstProgressDelta(tt.n)
			if got != tt.want {
				t.Errorf("verifyFirstProgressDelta(%d) = %d, want %d (the on-disk bytes counted in ctx.Total)",
					tt.n, got, tt.want)
			}
		})
	}
}

// TestVerifyFirstProgressNoOvershoot is the integration regression net for the VER-03
// acceptance criterion (REQUIREMENTS.md §VER-03): a verify-first RS decrypt reports
// monotonic progress that reaches but never exceeds 100% (<=50% in pass-1 terms),
// reaching exactly 50% at EOF.
//
// NOTE (D-13 reality): util.Statify already clamps the reported fraction to <=1.0, so
// this observable assertion holds for BOTH the buggy fixed-block increment and the
// faithful int64(n) fix — it cannot distinguish them. The falsifiable RED/GREEN signal
// for the fix lives in TestVerifyFirstProgressDeltaFaithful above; this test guards the
// user-visible contract against future regressions (e.g. an unclamped display).
//
// Non-block-aligned sizing: 200 full RS128 data blocks + a 37-byte partial tail across
// multiple 1 MiB-plaintext read chunks, so the verify loop emits several monotonic
// sub-0.5 samples plus an exact-0.5 EOF sample (non-vacuous: asserts >=1 pass-1 sample).
func TestVerifyFirstProgressNoOvershoot(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs: %v", err)
	}

	const password = "verify-first-progress-pw"

	// Span multiple verify read chunks (each ~1 MiB plaintext) with a non-block-aligned
	// tail (37 bytes over a 128-byte boundary) so the final RS block is partial.
	plaintext := make([]byte, 2*util.MiB+200*encoding.RS128DataSize+37)
	for i := range plaintext {
		plaintext[i] = byte(i % 251)
	}

	encryptedPath := encryptRSVolume(t, plaintext, password)

	rec := &recordingReporter{}
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   filepath.Join(t.TempDir(), "verify_first_progress.out"),
		Password:     password,
		VerifyFirst:  true,
		ForceDecrypt: false,
		Reporter:     rec,
		RSCodecs:     rsCodecs,
	}

	if err := Decrypt(context.Background(), decReq); err != nil {
		t.Fatalf("Decrypt with VerifyFirst failed: %v", err)
	}

	pass1 := rec.pass1Fractions()
	if len(pass1) == 0 {
		t.Fatal("no pass-1 (verifying) progress samples recorded — test is vacuous")
	}

	// (a) Never overshoots: every pass-1 fraction <= 0.5 (== 100% in pass-1 terms).
	for i, f := range pass1 {
		if f > 0.5 {
			t.Errorf("pass-1 progress sample %d = %v overshoots 0.5 (100%% pass-1)", i, f)
		}
	}

	// (b) Monotonic non-decreasing during pass 1.
	for i := 1; i < len(pass1); i++ {
		if pass1[i] < pass1[i-1] {
			t.Errorf("pass-1 progress not monotonic: sample %d = %v < sample %d = %v",
				i, pass1[i], i-1, pass1[i-1])
		}
	}

	// (c) Reaches exactly 0.5 (== 100% pass-1) at EOF.
	final := pass1[len(pass1)-1]
	if final != 0.5 {
		t.Errorf("final pass-1 progress = %v, want exactly 0.5 (100%% pass-1) at EOF", final)
	}
}
