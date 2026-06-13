package volume

import (
	"bytes"
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
	volPath := filepath.Join(tmpDir, "vol.pcv")
	if err := os.WriteFile(volPath, bytes.Repeat([]byte("x"), 2*1024*1024), 0644); err != nil {
		t.Fatalf("write volume: %v", err)
	}

	addRep := &etaStatusReporter{}
	if err := AddDeniability(volPath, "pw", addRep); err != nil {
		t.Fatalf("AddDeniability: %v", err)
	}
	if !hasSpeedAndETA(addRep.statuses) {
		t.Errorf("AddDeniability reported no speed+ETA status, got %v", addRep.statuses)
	}

	// The wrapped bytes are not a real inner volume, so RemoveDeniability fails
	// verification AFTER the streaming pass — which is all this test asserts.
	remRep := &etaStatusReporter{}
	_, _ = RemoveDeniability(volPath, "pw", remRep, rs)
	if !hasSpeedAndETA(remRep.statuses) {
		t.Errorf("RemoveDeniability reported no speed+ETA status, got %v", remRep.statuses)
	}
}
