package util

import (
	"strings"
	"testing"
)

func TestGenPassword(t *testing.T) {
	// Test with all character sets
	opts := PassgenOptions{
		Length:  32,
		Upper:   true,
		Lower:   true,
		Numbers: true,
		Symbols: true,
	}

	password, err := GenPassword(opts)
	if err != nil {
		t.Fatalf("GenPassword failed: %v", err)
	}

	if len(password) != 32 {
		t.Errorf("GenPassword length = %d; want 32", len(password))
	}

	// Generate multiple passwords and ensure they're different (randomness check)
	password2, err := GenPassword(opts)
	if err != nil {
		t.Fatalf("GenPassword failed: %v", err)
	}
	if password == password2 {
		t.Error("GenPassword generated identical passwords (unlikely if random)")
	}
}

func TestGenPasswordCharacterSets(t *testing.T) {
	// Test uppercase only
	opts := PassgenOptions{Length: 100, Upper: true}
	password, err := GenPassword(opts)
	if err != nil {
		t.Fatalf("GenPassword failed: %v", err)
	}
	for _, c := range password {
		if c < 'A' || c > 'Z' {
			t.Errorf("Uppercase-only password contains invalid char: %c", c)
		}
	}

	// Test lowercase only
	opts = PassgenOptions{Length: 100, Lower: true}
	password, err = GenPassword(opts)
	if err != nil {
		t.Fatalf("GenPassword failed: %v", err)
	}
	for _, c := range password {
		if c < 'a' || c > 'z' {
			t.Errorf("Lowercase-only password contains invalid char: %c", c)
		}
	}

	// Test numbers only
	opts = PassgenOptions{Length: 100, Numbers: true}
	password, err = GenPassword(opts)
	if err != nil {
		t.Fatalf("GenPassword failed: %v", err)
	}
	for _, c := range password {
		if c < '0' || c > '9' {
			t.Errorf("Numbers-only password contains invalid char: %c", c)
		}
	}

	// Test symbols only
	opts = PassgenOptions{Length: 100, Symbols: true}
	password, err = GenPassword(opts)
	if err != nil {
		t.Fatalf("GenPassword failed: %v", err)
	}
	validSymbols := "-=_+!@#$^&()?<>"
	for _, c := range password {
		if !strings.ContainsRune(validSymbols, c) {
			t.Errorf("Symbols-only password contains invalid char: %c", c)
		}
	}
}

func TestGenPasswordEmpty(t *testing.T) {
	// No character sets enabled should return empty
	opts := PassgenOptions{Length: 32}
	password, err := GenPassword(opts)
	if err != nil {
		t.Fatalf("GenPassword failed: %v", err)
	}
	if password != "" {
		t.Errorf("GenPassword with no charset should return empty, got %s", password)
	}

	// Zero length should return empty
	opts = PassgenOptions{Length: 0, Upper: true}
	password, err = GenPassword(opts)
	if err != nil {
		t.Fatalf("GenPassword failed: %v", err)
	}
	if password != "" {
		t.Errorf("GenPassword with zero length should return empty, got %s", password)
	}
}
