package volume

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"Picocrypt-NG/internal/encoding"
)

// etaStatusReporter captures every status string so a test can assert that a
// streaming pass reported throughput and ETA at some point.
type etaStatusReporter struct {
	statuses []string
}

func (r *etaStatusReporter) SetStatus(text string)                  { r.statuses = append(r.statuses, text) }
func (r *etaStatusReporter) SetProgress(fraction float32, _ string) {}
func (r *etaStatusReporter) SetCanCancel(can bool)                  {}
func (r *etaStatusReporter) Update()                                {}
func (r *etaStatusReporter) IsCancelled() bool                      { return false }

// assertStreamingSpeedAndETA fails unless the captured statuses prove a real
// streaming progress pass for the named operation. It is mutation-sensitive against
// the production status format ("... at %.2f MiB/s (ETA: %s)"):
//   - (a) at least two statuses match the "MiB/s"+"ETA:" shape (a single sample
//     would mean no streaming loop, just one bookend report);
//   - (b) at least one sample carries a parsed speed strictly > 0 (a "0.00 MiB/s"
//     status means the speed math never ran / was stubbed out);
//   - (c) at least one sample carries a non-empty token after "ETA: " (a dropped
//     ETA field would leave the parenthesis empty).
func assertStreamingSpeedAndETA(t *testing.T, op string, statuses []string) {
	t.Helper()

	matches := 0
	sawPositiveSpeed := false
	sawNonEmptyETA := false
	for _, s := range statuses {
		if !strings.Contains(s, "MiB/s") || !strings.Contains(s, "ETA:") {
			continue
		}
		matches++

		// Parse the float immediately preceding " MiB/s": take the text before that
		// marker and read the final whitespace-delimited token as the speed.
		if prefix, _, ok := strings.Cut(s, " MiB/s"); ok {
			fields := strings.Fields(prefix)
			if len(fields) > 0 {
				if speed, err := strconv.ParseFloat(fields[len(fields)-1], 64); err == nil && speed > 0 {
					sawPositiveSpeed = true
				}
			}
		}

		// Extract the ETA token between "ETA: " and the closing ")".
		if _, after, ok := strings.Cut(s, "ETA: "); ok {
			eta, _, _ := strings.Cut(after, ")")
			if strings.TrimSpace(eta) != "" {
				sawNonEmptyETA = true
			}
		}
	}

	if matches < 2 {
		t.Errorf("%s: got %d speed+ETA statuses, want >=2 (streaming should report multiple samples); statuses=%v", op, matches, statuses)
	}
	if !sawPositiveSpeed {
		t.Errorf("%s: no status reported a speed > 0 MiB/s; statuses=%v", op, statuses)
	}
	if !sawNonEmptyETA {
		t.Errorf("%s: no status reported a non-empty ETA token; statuses=%v", op, statuses)
	}
}

// TestDeniabilityReportsSpeedAndETA verifies both deniability passes report a
// status with throughput and ETA while streaming, like the encrypt/decrypt
// payload passes — not just a bare percentage. The fast KDF stub installed by
// TestMain keeps the Argon2 derivation cheap.
func TestDeniabilityReportsSpeedAndETA(t *testing.T) {
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs: %v", err)
	}
	tmpDir := t.TempDir()

	// AddDeniability encrypts whatever bytes it is given, so a plain 2 MiB blob
	// exercises its streaming progress reporting.
	addPath := filepath.Join(tmpDir, "add.bin")
	if err := os.WriteFile(addPath, bytes.Repeat([]byte("x"), 2*1024*1024), 0644); err != nil {
		t.Fatalf("write add input: %v", err)
	}
	addRep := &etaStatusReporter{}
	if err := AddDeniability(addPath, []byte("pw"), addRep); err != nil {
		t.Fatalf("AddDeniability: %v", err)
	}
	assertStreamingSpeedAndETA(t, "AddDeniability", addRep.statuses)

	// RemoveDeniability now selects the password form by probing the inner
	// version field before streaming, so it must operate on a REAL deniable
	// volume to reach (and report on) the streaming pass. Build one: encrypt a
	// 2 MiB file, then wrap it.
	plainPath := filepath.Join(tmpDir, "pt.bin")
	if err := os.WriteFile(plainPath, bytes.Repeat([]byte("y"), 2*1024*1024), 0644); err != nil {
		t.Fatalf("write plaintext: %v", err)
	}
	volPath := filepath.Join(tmpDir, "vol.pcv")
	if err := Encrypt(context.Background(), &EncryptRequest{
		InputFile: plainPath, OutputFile: volPath, Password: []byte("pw"),
		Reporter: &GoldenTestReporter{}, RSCodecs: rs,
	}); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if err := AddDeniability(volPath, []byte("pw"), &etaStatusReporter{}); err != nil {
		t.Fatalf("AddDeniability(volume): %v", err)
	}

	remRep := &etaStatusReporter{}
	if _, err := RemoveDeniability(volPath, []byte("pw"), remRep, rs); err != nil {
		t.Fatalf("RemoveDeniability: %v", err)
	}
	assertStreamingSpeedAndETA(t, "RemoveDeniability", remRep.statuses)
}
