package cli

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// Version is set by main.go
var Version = "dev"

const (
	ExitGeneralError     = 1
	ExitForceDecryptKept = 2
)

type ExitCodeError interface {
	error
	ExitCode() int
}

type exitCodeError struct {
	message string
	code    int
}

func newExitCodeError(code int, message string) error {
	return exitCodeError{
		message: message,
		code:    code,
	}
}

func (e exitCodeError) Error() string {
	return e.message
}

func (e exitCodeError) ExitCode() int {
	return e.code
}

func exitCodeForError(err error) int {
	if err == nil {
		return 0
	}

	var exitErr ExitCodeError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return ExitGeneralError
}

func isExitCodeError(err error) bool {
	var exitErr ExitCodeError
	return errors.As(err, &exitErr)
}

// rootCmd is the base command when called without subcommands
var rootCmd = &cobra.Command{
	Use:   "Picocrypt-NG",
	Short: "Secure file encryption tool",
	Long: `Picocrypt-NG is a secure, audited file encryption tool that uses:
  - Argon2id for password-based key derivation (memory-hard, GPU-resistant)
  - XChaCha20 for symmetric encryption (256-bit security, extended nonce)
  - BLAKE2b-512 for message authentication (or HMAC-SHA3 in paranoid mode)
  - Optional Serpent-CTR as second cipher layer (paranoid mode)
  - Reed-Solomon error correction for data recovery`,
	Version: Version,
}

// Global reporter for signal handling (atomic for safe concurrent access)
var globalReporter atomic.Pointer[Reporter]

// Execute runs the CLI application.
// Returns true if CLI mode was activated, false if GUI should run instead.
func Execute(version string) bool {
	Version = version
	rootCmd.Version = version

	if !detectCLIMode(os.Args[1:]) {
		return false
	}

	// Set up signal handling for graceful cancellation
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		if r := globalReporter.Load(); r != nil {
			r.Cancel()
			fmt.Fprintln(os.Stderr, "\nCancelling operation...")
		} else {
			os.Exit(1)
		}
	}()

	if err := rootCmd.Execute(); err != nil {
		if !isExitCodeError(err) {
			fmt.Fprintln(os.Stderr, "Error:", err)
		}
		os.Exit(exitCodeForError(err))
	}
	return true
}

func detectCLIMode(args []string) bool {
	if len(args) == 0 {
		return false
	}

	for _, arg := range args {
		if arg == "-h" || arg == "--help" || arg == "-v" || arg == "--version" {
			return true
		}
	}

	index := 0
	for index < len(args) {
		arg := args[index]
		if arg == "--" {
			index++
			break
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			break
		}

		flagToken := arg
		hasInlineValue := false
		if before, _, ok := strings.Cut(arg, "="); ok {
			flagToken = before
			hasInlineValue = true
		}

		flag := lookupRootPersistentFlag(flagToken)
		if flag == nil {
			return hasKnownRootCommand(args[index+1:])
		}

		if flag.NoOptDefVal == "" && !hasInlineValue {
			nextIndex := index + 1
			if nextIndex >= len(args) {
				return true
			}
			if isKnownRootCommand(args[nextIndex]) {
				return true
			}
			index = nextIndex
		}

		index++
	}

	if index >= len(args) {
		return false
	}

	return isKnownRootCommand(args[index])
}

func lookupRootPersistentFlag(token string) *pflag.Flag {
	switch {
	case strings.HasPrefix(token, "--"):
		return rootCmd.PersistentFlags().Lookup(strings.TrimPrefix(token, "--"))
	case strings.HasPrefix(token, "-") && len(token) == 2:
		return rootCmd.PersistentFlags().ShorthandLookup(strings.TrimPrefix(token, "-"))
	default:
		return nil
	}
}

func hasKnownRootCommand(args []string) bool {
	for _, arg := range args {
		if isKnownRootCommand(arg) {
			return true
		}
	}

	return false
}

func isKnownRootCommand(token string) bool {
	if token == "help" {
		return true
	}

	for _, cmd := range rootCmd.Commands() {
		if cmd.Name() == token {
			return true
		}
		for _, alias := range cmd.Aliases {
			if alias == token {
				return true
			}
		}
	}

	return false
}

func init() {
	// Disable default completion command
	rootCmd.CompletionOptions.DisableDefaultCmd = true

	// Global flags
	rootCmd.PersistentFlags().StringVar(&TempDirOverride, "temp-dir", "", "Directory for temp files (overrides automatic selection)")
}
