package volume

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
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

func hasSpeedAndETA(statuses []string) bool {
	for _, s := range statuses {
		if strings.Contains(s, "MiB/s") && strings.Contains(s, "ETA:") {
			return true
		}
	}
	return false
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
	if err := AddDeniability(addPath, "pw", addRep); err != nil {
		t.Fatalf("AddDeniability: %v", err)
	}
	if !hasSpeedAndETA(addRep.statuses) {
		t.Errorf("AddDeniability reported no speed+ETA status, got %v", addRep.statuses)
	}

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
		InputFile: plainPath, OutputFile: volPath, Password: "pw",
		Reporter: &GoldenTestReporter{}, RSCodecs: rs,
	}); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if err := AddDeniability(volPath, "pw", &etaStatusReporter{}); err != nil {
		t.Fatalf("AddDeniability(volume): %v", err)
	}

	remRep := &etaStatusReporter{}
	if _, err := RemoveDeniability(volPath, "pw", remRep, rs); err != nil {
		t.Fatalf("RemoveDeniability: %v", err)
	}
	if !hasSpeedAndETA(remRep.statuses) {
		t.Errorf("RemoveDeniability reported no speed+ETA status, got %v", remRep.statuses)
	}
}
