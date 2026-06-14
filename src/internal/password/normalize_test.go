package password

import (
	"bytes"
	"testing"
)

// Worked Unicode vectors (UAX #15). These pin the exact cross-platform mismatch
// issue #19 targets: the same visible character in composed (NFC) vs decomposed
// (NFD) byte forms, which derive different Argon2 keys when fed raw.
const (
	eComposed    = "é"             // é  NFC  -> C3 A9
	eDecomposed  = "é"            // é  NFD  -> 65 CC 81
	gaComposed   = "가"             // 가 NFC  -> EA B0 80
	gaDecomposed = "가"       // 가 NFD  -> E1 84 80 E1 85 A1
	devEmoji     = "\U0001f469‍\U0001f4bb" // 👩‍💻 ZWJ sequence, unchanged by NFC/NFD
)

var (
	eNFCBytes  = []byte{0xc3, 0xa9}
	eNFDBytes  = []byte{0x65, 0xcc, 0x81}
	gaNFCBytes = []byte{0xea, 0xb0, 0x80}
)

func TestNormalizeProducesNFC(t *testing.T) {
	// Composed and decomposed forms of the SAME character must normalize to
	// identical NFC bytes — that is exactly what lets a password typed on one
	// platform derive the same key as on another (the #19 fix). If Normalize
	// stopped normalizing, these would diverge and the test fails.
	cases := []struct {
		name string
		in   string
		want []byte
	}{
		{"é composed", eComposed, eNFCBytes},
		{"é decomposed", eDecomposed, eNFCBytes},
		{"가 composed", gaComposed, gaNFCBytes},
		{"가 decomposed", gaDecomposed, gaNFCBytes},
	}
	for _, tc := range cases {
		if got := []byte(Normalize(tc.in)); !bytes.Equal(got, tc.want) {
			t.Errorf("Normalize(%s) = % x, want % x", tc.name, got, tc.want)
		}
	}
}

func TestNormalizeIsIdempotent(t *testing.T) {
	for _, in := range []string{eComposed, eDecomposed, gaDecomposed, devEmoji, "ascii"} {
		once := Normalize(in)
		if twice := Normalize(once); twice != once {
			t.Errorf("Normalize not idempotent for %q: %q != %q", in, twice, once)
		}
	}
}

func TestNormalizeLeavesASCIIUnchanged(t *testing.T) {
	// ASCII is invariant under NFC, so the millions of existing ASCII-password
	// volumes are completely unaffected by this change.
	in := "Correct Horse Battery Staple 123!@#"
	if got := Normalize(in); got != in {
		t.Errorf("Normalize(ascii) = %q, want unchanged %q", got, in)
	}
}

func TestNormalizeDoesNotCaseFoldOrTrim(t *testing.T) {
	// NFC must preserve case (RFC 8265 §4.2.2: no case mapping — folding the
	// Turkish dotless-i class reduces security) and must NOT trim whitespace
	// (silent entropy loss / lockouts). ß must not fold to "ss".
	in := " straße "
	if got := Normalize(in); got != in {
		t.Errorf("Normalize must preserve ß and surrounding spaces: %q -> %q", in, got)
	}
}

func TestNormalizeLeavesEmojiZWJUnchanged(t *testing.T) {
	// ZWJ emoji sequences have no canonical decomposition; NFC passes them
	// through byte-for-byte, so emoji passwords are never corrupted.
	if got := Normalize(devEmoji); got != devEmoji {
		t.Errorf("Normalize altered ZWJ emoji: % x -> % x", []byte(devEmoji), []byte(got))
	}
}

func TestEncodeForKDFIsNFCBytes(t *testing.T) {
	// Encrypt must feed the KDF the NFC form regardless of how the password was
	// typed, so new volumes are cross-platform-stable.
	if got := EncodeForKDF(eDecomposed); !bytes.Equal(got, eNFCBytes) {
		t.Errorf("EncodeForKDF(decomposed é) = % x, want NFC % x", got, eNFCBytes)
	}
}

func TestCandidatesASCIISingleAttempt(t *testing.T) {
	// The common case: ASCII passwords yield exactly ONE candidate (raw bytes),
	// guaranteeing no extra Argon2 work and no behavior change. If this grew to
	// >1, every ASCII wrong-password would pay multiple 1 GiB derivations.
	got := Candidates("password123")
	if len(got) != 1 {
		t.Fatalf("ASCII Candidates len = %d, want 1 (got % x)", len(got), got)
	}
	if !bytes.Equal(got[0], []byte("password123")) {
		t.Errorf("ASCII candidate = % x, want raw bytes", got[0])
	}
}

func TestCandidatesNonASCIIOrderAndDedup(t *testing.T) {
	// NFC must be tried FIRST (so a correct password on a new/NFC volume matches
	// on the first derivation) and duplicate forms must be collapsed (so we
	// never run the same Argon2 twice). For a composed-é password NFC == raw, so
	// after dedup we expect exactly [NFC, NFD].
	for _, in := range []string{eComposed, eDecomposed} {
		got := Candidates(in)
		if len(got) != 2 {
			t.Fatalf("Candidates(%q) len = %d, want 2 (got % x)", in, len(got), got)
		}
		if !bytes.Equal(got[0], eNFCBytes) {
			t.Errorf("Candidates(%q)[0] = % x, want NFC % x", in, got[0], eNFCBytes)
		}
		if !bytes.Equal(got[1], eNFDBytes) {
			t.Errorf("Candidates(%q)[1] = % x, want NFD % x", in, got[1], eNFDBytes)
		}
	}
}

func TestCandidatesIncludesRawWhenNeitherNFCNorNFD(t *testing.T) {
	// A non-canonical input (combining marks out of canonical order) differs
	// from BOTH its NFC and NFD forms, so raw MUST be kept as a third candidate
	// to keep such legacy volumes decryptable. "e" + U+0301 (acute, ccc=230) +
	// U+0323 (dot-below, ccc=220): canonical order requires 220 before 230, so
	// this raw ordering is non-canonical and is preserved by neither NFC nor NFD.
	nonCanonical := "ẹ́"
	got := Candidates(nonCanonical)
	if len(got) != 3 {
		t.Fatalf("Candidates(non-canonical) len = %d, want 3 (got % x)", len(got), got)
	}
	if !bytes.Equal(got[2], []byte(nonCanonical)) {
		t.Errorf("Candidates[2] = % x, want raw % x", got[2], []byte(nonCanonical))
	}
	if bytes.Equal(got[0], []byte(nonCanonical)) || bytes.Equal(got[1], []byte(nonCanonical)) {
		t.Errorf("raw must be distinct from NFC/NFD candidates for a non-canonical input")
	}
}

func TestCandidatesEmptyPassword(t *testing.T) {
	got := Candidates("")
	if len(got) != 1 || len(got[0]) != 0 {
		t.Errorf("Candidates(\"\") = %v, want a single empty candidate", got)
	}
}
