package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

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

func readPasswordLine(reader *bufio.Reader) (string, error) {
	pw, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}

	pw = strings.TrimSuffix(pw, "\n")
	pw = strings.TrimSuffix(pw, "\r")
	return pw, nil
}

// readPasswordSecure reads a password from stdin without echo.
// Falls back to buffered read if stdin is not a terminal.
func readPasswordSecure(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)

	if !isTerminal() {
		// stdin is piped; read normally
		reader := bufio.NewReader(os.Stdin)
		pw, err := readPasswordLine(reader)
		if err != nil {
			return "", fmt.Errorf("reading password: %w", err)
		}
		return pw, nil
	}

	// Terminal mode: capture the current tty state so a SIGINT during the
	// no-echo read can be restored by the signal handler (os.Exit skips
	// term.ReadPassword's own deferred restore).
	captureTerminalState()

	// Terminal mode: disable echo
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr) // newline after hidden input
	if err != nil {
		return "", fmt.Errorf("reading password: %w", err)
	}
	return string(pw), nil
}

// ReadPasswordInteractive prompts for password interactively.
// If confirm is true, asks for confirmation (for encryption).
// If allowEmpty is true, empty password is allowed (useful when keyfiles provide credentials).
func ReadPasswordInteractive(confirm, allowEmpty bool) (string, error) {
	// Once the prompt(s) have returned normally, clear the saved tty state so a
	// later unrelated signal does not re-poke the terminal.
	defer savedTerminalState.Store(nil)

	password, err := readPasswordSecure("Password: ")
	if err != nil {
		return "", err
	}

	if password == "" && !allowEmpty {
		return "", ErrPasswordEmpty
	}

	if confirm && password != "" {
		confirmPw, err := readPasswordSecure("Confirm password: ")
		if err != nil {
			return "", err
		}
		if password != confirmPw {
			return "", ErrPasswordMismatch
		}
	}

	return password, nil
}

// ReadPasswordFromStdin reads password from stdin (for piped input with -P flag).
func ReadPasswordFromStdin() (string, error) {
	reader := bufio.NewReader(os.Stdin)
	pw, err := readPasswordLine(reader)
	if err != nil {
		return "", fmt.Errorf("reading password from stdin: %w", err)
	}
	return pw, nil
}
