package app

import "testing"

func newStateForTest(t *testing.T) *State {
	t.Helper()
	s, err := NewState()
	if err != nil {
		t.Fatalf("NewState: %v", err)
	}
	return s
}

// TestRecursiveSnapshotCapturesFields proves RecursiveSnapshot copies every
// field the recursive batch worker restores, and deep-copies Keyfiles so the
// captured settings cannot be mutated through State after the lock is released
// (APP-02: the recursive worker must not read State unlocked).
func TestRecursiveSnapshotCapturesFields(t *testing.T) {
	s := newStateForTest(t)
	s.Password = "pw"
	s.Keyfile = true
	s.Keyfiles = []string{"a", "b"}
	s.KeyfileOrdered = true
	s.Comments = "c"
	s.Paranoid = true
	s.ReedSolomon = true
	s.Deniability = true
	s.Split = true
	s.SplitSize = "64"
	s.SplitSelected = 2
	s.Delete = true

	snap := s.RecursiveSnapshot()

	if snap.Password != "pw" || !snap.Keyfile || !snap.KeyfileOrdered ||
		snap.Comments != "c" || !snap.Paranoid || !snap.ReedSolomon || !snap.Deniability || !snap.Split ||
		snap.SplitSize != "64" || snap.SplitSelected != 2 || !snap.Delete {
		t.Fatalf("RecursiveSnapshot did not capture all fields: %+v", snap)
	}
	if len(snap.Keyfiles) != 2 || snap.Keyfiles[0] != "a" || snap.Keyfiles[1] != "b" {
		t.Fatalf("Keyfiles not captured: %v", snap.Keyfiles)
	}

	// Mutating State afterwards must not reach into the snapshot.
	s.Keyfiles[0] = "mutated"
	if snap.Keyfiles[0] != "a" {
		t.Error("RecursiveSnapshot.Keyfiles aliases State's backing array (not deep-copied)")
	}
}

// TestApplyRecursiveSelectionRestoresFields proves ApplyRecursiveSelection writes
// every captured field back under the lock, mirrors CPassword from Password
// (recursive mode never re-confirms), and deep-copies Keyfiles.
func TestApplyRecursiveSelectionRestoresFields(t *testing.T) {
	s := newStateForTest(t)
	s.Mode = "encrypt"

	rs := RecursiveSnapshot{
		Password:       "pw",
		Keyfile:        true,
		Keyfiles:       []string{"a"},
		KeyfileOrdered: true,
		Comments:       "c",
		Paranoid:       true,
		ReedSolomon:    true,
		Deniability:    true,
		Split:          true,
		SplitSize:      "64",
		SplitSelected:  2,
		Delete:         true,
	}
	s.ApplyRecursiveSelection(rs)

	if s.Password != "pw" || s.CPassword != "pw" {
		t.Fatalf("password/cpassword not restored: %q / %q", s.Password, s.CPassword)
	}
	if !s.Keyfile || !s.KeyfileOrdered || s.Comments != "c" || !s.Paranoid || !s.ReedSolomon || !s.Deniability ||
		!s.Split || s.SplitSize != "64" || s.SplitSelected != 2 || !s.Delete {
		t.Fatal("ApplyRecursiveSelection did not restore all fields")
	}
	if len(s.Keyfiles) != 1 || s.Keyfiles[0] != "a" {
		t.Fatalf("Keyfiles not restored: %v", s.Keyfiles)
	}

	// Mutating the snapshot afterwards must not reach back into State.
	rs.Keyfiles[0] = "mutated"
	if s.Keyfiles[0] != "a" {
		t.Error("ApplyRecursiveSelection aliases the snapshot's Keyfiles backing array")
	}
}

// TestApplyRecursiveSelectionSkipsDeniabilityOnDecrypt proves Deniability — an
// encrypt-only option — is left untouched when the just-dropped file put the
// State into decrypt mode (preserves the prior inline `Mode != "decrypt"` guard).
func TestApplyRecursiveSelectionSkipsDeniabilityOnDecrypt(t *testing.T) {
	s := newStateForTest(t)
	s.Mode = "decrypt"
	s.Deniability = false

	s.ApplyRecursiveSelection(RecursiveSnapshot{Deniability: true})

	if s.Deniability {
		t.Error("ApplyRecursiveSelection applied Deniability in decrypt mode (should be skipped)")
	}
}
