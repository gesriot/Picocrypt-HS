// Picocrypt NG v2.01
// Copyright (c) Picocrypt NG developers
// Released under GPL-3.0-only
// https://github.com/Picocrypt-NG/Picocrypt-NG
//
// Picocrypt NG is a secure, audited file encryption tool that uses:
//   - Argon2id for password-based key derivation (memory-hard, GPU-resistant)
//   - XChaCha20 for symmetric encryption (256-bit security, extended nonce)
//   - BLAKE2b-512 for message authentication (or HMAC-SHA3 in paranoid mode)
//   - Optional Serpent-CTR as second cipher layer (paranoid mode)
//   - Reed-Solomon error correction for data recovery
//   - Plausible deniability through nested encryption
//
// The cryptographic implementation was audited in August 2024.

package main

import (
	"flag"
	"fmt"
	"os"

	"Picocrypt-NG/internal/ui"
)

// version is the application version displayed in the window title.
// Format: "vMAJOR.MINOR" (e.g., "v2.01")
const version = "v2.01"

func main() {
	flag.Parse()

	// Initialize and run the graphical user interface.
	// The UI handles drag-and-drop file selection, encryption options,
	// progress reporting, and all user interactions.
	app, err := ui.NewApp(version)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize: %v\n", err)
		os.Exit(1)
	}

	app.Run()
}
