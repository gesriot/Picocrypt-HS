package cli

import (
	"Picocrypt-NG/internal/crypto"
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	pwnorm "Picocrypt-NG/internal/password"

	"golang.org/x/term"
)

var (
	ErrPasswordMismatch = errors.New("passwords do not match")
	ErrPasswordEmpty    = errors.New("password cannot be empty")
)

// isTerminal returns true if stdin is a terminal (not piped/redirected).
func isTerminal() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

// captureTerminalState records the current tty mode so the signal handler can
// restore it if SIGINT arrives during a no-echo password read. A GetState error
// (e.g. fd is not a tty) stores nothing, leaving restore a no-op.
func captureTerminalState() {
	if st, err := term.GetState(int(os.Stdin.Fd())); err == nil {
		savedTerminalState.Store(st)
	}
}

func readPasswordLine(reader *bufio.Reader) ([]byte, error) {
	pw, err := reader.ReadBytes('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}

	pw = bytes.TrimSuffix(pw, []byte("\n"))
	pw = bytes.TrimSuffix(pw, []byte("\r"))
	return pw, nil
}

// readPasswordSecure reads a password from stdin without echo, returning owned
// []byte the caller can zero. Falls back to buffered read if stdin is not a
// terminal.
func readPasswordSecure(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)

	if !isTerminal() {
		// stdin is piped; read normally
		reader := bufio.NewReader(os.Stdin)
		pw, err := readPasswordLine(reader)
		if err != nil {
			return nil, fmt.Errorf("reading password: %w", err)
		}
		return pw, nil
	}

	// Terminal mode: capture the current tty state so a SIGINT during the
	// no-echo read can be restored by the signal handler (os.Exit skips
	// term.ReadPassword's own deferred restore).
	captureTerminalState()

	// Terminal mode: disable echo. term.ReadPassword returns an owned []byte.
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr) // newline after hidden input
	if err != nil {
		return nil, fmt.Errorf("reading password: %w", err)
	}
	return pw, nil
}

// ReadPasswordInteractive prompts for password interactively.
// If confirm is true, asks for confirmation (for encryption).
// If allowEmpty is true, empty password is allowed (useful when keyfiles provide credentials).
// nonASCIIPasswordNote returns an advisory to show when an ENCRYPTION password
// (confirm == true) contains non-ASCII characters, or "" when none is warranted.
// The password is normalized (NFC) for cross-platform decryption, but the user
// should still be able to reproduce the exact characters elsewhere — NIST
// SP 800-63B-4 recommends advising this.
func nonASCIIPasswordNote(confirm bool, password []byte) string {
	if confirm && pwnorm.ContainsNonASCII(password) {
		return "Note: your password contains non-ASCII characters. They are normalized " +
			"for cross-platform decryption, but make sure you can type the same " +
			"characters on every device where you'll decrypt this volume."
	}
	return ""
}

func ReadPasswordInteractive(confirm, allowEmpty bool) ([]byte, error) {
	// Once the prompt(s) have returned normally, clear the saved tty state so a
	// later unrelated signal does not re-poke the terminal.
	defer savedTerminalState.Store(nil)

	password, err := readPasswordSecure("Password: ")
	if err != nil {
		return nil, err
	}

	if len(password) == 0 && !allowEmpty {
		return nil, ErrPasswordEmpty
	}

	if confirm && len(password) > 0 {
		confirmPw, err := readPasswordSecure("Confirm password: ")
		if err != nil {
			return nil, err
		}
		// Zero the confirmation copy once compared; only `password` is returned.
		defer crypto.SecureZero(confirmPw)
		if !bytes.Equal(password, confirmPw) {
			return nil, ErrPasswordMismatch
		}
	}

	if note := nonASCIIPasswordNote(confirm, password); note != "" {
		fmt.Fprintln(os.Stderr, note)
	}

	return password, nil
}

// ReadPasswordFromStdin reads password from stdin (for piped input with -P flag).
func ReadPasswordFromStdin() ([]byte, error) {
	reader := bufio.NewReader(os.Stdin)
	pw, err := readPasswordLine(reader)
	if err != nil {
		return nil, fmt.Errorf("reading password from stdin: %w", err)
	}
	return pw, nil
}
