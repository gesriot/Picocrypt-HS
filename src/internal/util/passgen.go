package util

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

// RandomBytes generates n cryptographically secure random bytes.
func RandomBytes(n int) ([]byte, error) {
	if n <= 0 {
		return nil, errors.New("invalid length")
	}
	data := make([]byte, n)
	if _, err := rand.Read(data); err != nil {
		return nil, err
	}
	return data, nil
}

// PassgenOptions configures the password generator.
type PassgenOptions struct {
	Length  int
	Upper   bool
	Lower   bool
	Numbers bool
	Symbols bool
}

// GenPassword generates a cryptographically secure password based on the given options.
// Returns an empty string and nil error if no character sets are enabled.
// Returns an error if the cryptographic random number generator fails.
func GenPassword(opts PassgenOptions) (string, error) {
	chars := ""
	if opts.Upper {
		chars += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	}
	if opts.Lower {
		chars += "abcdefghijklmnopqrstuvwxyz"
	}
	if opts.Numbers {
		chars += "1234567890"
	}
	if opts.Symbols {
		chars += "-=_+!@#$^&()?<>"
	}

	if len(chars) == 0 || opts.Length <= 0 {
		return "", nil
	}

	tmp := make([]byte, opts.Length)
	for i := range opts.Length {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return "", fmt.Errorf("fatal crypto/rand error: %w", err)
		}
		tmp[i] = chars[j.Int64()]
	}
	return string(tmp), nil
}
