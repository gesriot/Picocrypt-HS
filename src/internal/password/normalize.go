// Package password normalizes user passwords to Unicode NFC before the key
// derivation function, fixing the cross-platform (NFC vs NFD) key mismatch
// described in issue #19: a visually identical password typed on macOS
// (sometimes decomposed) versus Windows/Linux (composed) is byte-different and
// therefore derives a different Argon2 key, so a volume encrypted on one
// platform cannot be decrypted on another.
//
// The normalization form is NFC, mandated for passwords by RFC 8265 (PRECIS
// OpaqueString profile) and recommended by NIST SP 800-63B-4 §3.1.1.2. This
// package deliberately applies ONLY canonical composition. It does NOT apply:
//
//   - compatibility normalization (NFKC/NFKD), which collapses distinct
//     characters (e.g. fullwidth/halfwidth, ﬀ→ff) and reduces password entropy;
//   - case folding, which RFC 8265 omits because it causes false accepts and
//     enables the Turkish dotless-i collision class;
//   - whitespace trimming, which silently reduces entropy and causes lockouts.
//
// ASCII input is invariant under NFC and is handled without extra work, so the
// overwhelming majority of existing (ASCII-password) volumes are unaffected.
package password

import (
	"bytes"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// Normalize returns pw in Unicode Normalization Form C (NFC).
func Normalize(pw string) string {
	return norm.NFC.String(pw)
}

// EncodeForKDF returns the NFC-normalized password as UTF-8 bytes to feed the
// KDF when ENCRYPTING, so new volumes derive a canonical, cross-platform-stable
// key regardless of how the password was typed.
func EncodeForKDF(pw string) []byte {
	return []byte(Normalize(pw))
}

// Candidates returns the ordered, de-duplicated password byte forms to try when
// DECRYPTING, so volumes stay decryptable across platforms and across the
// pre/post-normalization format change.
//
// For an ASCII password it returns exactly one candidate (the raw bytes): ASCII
// is invariant under every normalization form, so there is no extra KDF work
// for the common case. For a non-ASCII password it returns up to three forms,
// duplicates removed while preserving order:
//
//  1. NFC  — opens new volumes and legacy ASCII/NFC volumes; tried first so a
//     correct password matches on the first (and only) derivation.
//  2. NFD  — opens legacy volumes whose password was decomposed.
//  3. raw  — opens legacy volumes whose bytes were neither NFC nor NFD (e.g. a
//     password pasted with combining marks in non-canonical order).
//
// Each candidate is authenticated independently against the volume MAC by the
// caller; trying several canonical forms of the SAME password never bypasses
// authentication, and the extra derivations only occur when an earlier form
// fails to verify (i.e. a wrong password or a legacy non-NFC volume).
//
// Returned slices are independent allocations, so a caller may zero each one
// after use without affecting the others.
func Candidates(pw string) [][]byte {
	if !ContainsNonASCII(pw) {
		// ASCII is invariant under every normalization form, so a single
		// candidate suffices and there is no extra KDF work for the common case.
		return [][]byte{[]byte(pw)}
	}

	// Distinct allocations (not norm.*.Bytes, which may alias) so the caller can
	// zero each candidate independently.
	forms := [3][]byte{
		[]byte(norm.NFC.String(pw)),
		[]byte(norm.NFD.String(pw)),
		[]byte(pw),
	}

	candidates := make([][]byte, 0, len(forms))
	for _, f := range forms {
		if !containsBytes(candidates, f) {
			candidates = append(candidates, f)
		}
	}
	return candidates
}

// ContainsNonASCII reports whether pw contains any non-ASCII byte. User
// interfaces use it to advise that a non-ASCII password — while normalized to a
// canonical form for cross-platform decryption — may still be hard to reproduce
// on another device with a different keyboard or input method (NIST
// SP 800-63B-4 recommends informing users of this).
func ContainsNonASCII(pw string) bool {
	for i := 0; i < len(pw); i++ {
		if pw[i] >= utf8.RuneSelf {
			return true
		}
	}
	return false
}

// containsBytes reports whether set already holds a slice byte-equal to b. A
// linear scan over at most three short slices is cheaper than a map and, unlike
// a map keyed by string(b), creates no extra in-memory copies of the password.
func containsBytes(set [][]byte, b []byte) bool {
	for _, e := range set {
		if bytes.Equal(e, b) {
			return true
		}
	}
	return false
}
