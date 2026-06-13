package diskspace

import "testing"

func TestAvailable(t *testing.T) {
	space, err := Available(t.TempDir())
	if err != nil {
		t.Fatalf("Available() error = %v", err)
	}
	if space <= 0 {
		t.Errorf("Available() = %d, want > 0", space)
	}
}

func TestAvailableNonExistentPath(t *testing.T) {
	if _, err := Available("/nonexistent/path/that/does/not/exist"); err == nil {
		t.Error("Available() on non-existent path: expected error, got nil")
	}
}
