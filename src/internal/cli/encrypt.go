package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/volume"

	"github.com/spf13/cobra"
)

func init() {
	// Silence Cobra's default error/usage printing - we handle it ourselves
	encryptCmd.SilenceErrors = true
	encryptCmd.SilenceUsage = true
}

var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Encrypt files into a .pcv volume",
	Long: `Encrypt one or more files into a Picocrypt volume (.pcv).

If no password is provided, you will be prompted to enter one interactively
(with confirmation). The password is hidden while typing.

Examples:
  # Encrypt interactively (prompts for password)
  Picocrypt-NG encrypt -i secret.txt -o secret.pcv

  # Encrypt with password on command line (visible in shell history)
  Picocrypt-NG encrypt -i secret.txt -o secret.pcv -p "mypassword"

  # Encrypt multiple files (creates zip archive internally)
  Picocrypt-NG encrypt -i file1.txt -i file2.txt -o archive.pcv

  # Encrypt with paranoid mode and Reed-Solomon error correction
  Picocrypt-NG encrypt -i data.db -o data.pcv --paranoid --reed-solomon

  # Encrypt with keyfile (prompts for password, can leave empty for keyfile-only)
  Picocrypt-NG encrypt -i secret.txt -o secret.pcv -k keyfile.key

  # Encrypt with keyfile only (no password)
  Picocrypt-NG encrypt -i secret.txt -o secret.pcv -k keyfile.key -p ""

  # Read password from stdin (for scripts)
  echo "mypassword" | Picocrypt-NG encrypt -i secret.txt -o secret.pcv -P

  # Encrypt from stdin to stdout (use -p since stdin is taken by data)
  cat data.txt | Picocrypt-NG encrypt -i - -o - -p "pw" > data.pcv

  # Encrypt to stdout
  Picocrypt-NG encrypt -i secret.txt -o - -p "pw" > secret.pcv`,
	RunE: runEncrypt,
}

// Encrypt flags
var (
	encInput          []string
	encOutput         string
	encPassword       string
	encPasswordStdin  bool
	encKeyfiles       []string
	encKeyfileOrder   bool
	encComments       string
	encParanoid       bool
	encReedSolomon    bool
	encDeniability    bool
	encCompress       bool
	encSplit          bool
	encSplitSize      int
	encSplitUnit      string
	encQuiet          bool
	encYes            bool
	encFollowSymlinks bool
)

func init() {
	rootCmd.AddCommand(encryptCmd)

	// Input/Output
	encryptCmd.Flags().StringArrayVarP(&encInput, "input", "i", nil, "Input file(s) to encrypt (can be specified multiple times)")
	encryptCmd.Flags().StringVarP(&encOutput, "output", "o", "", "Output .pcv file path")

	// Credentials
	encryptCmd.Flags().StringVarP(&encPassword, "password", "p", "", "Encryption password")
	encryptCmd.Flags().BoolVarP(&encPasswordStdin, "password-stdin", "P", false, "Read password from stdin")
	encryptCmd.Flags().StringArrayVarP(&encKeyfiles, "keyfile", "k", nil, "Keyfile path(s) (can be specified multiple times)")
	encryptCmd.Flags().BoolVar(&encKeyfileOrder, "keyfile-ordered", false, "Keyfile order matters (sequential hashing)")

	// Security options
	encryptCmd.Flags().StringVarP(&encComments, "comments", "c", "", "Comments to store in header (NOT encrypted)")
	encryptCmd.Flags().BoolVar(&encParanoid, "paranoid", false, "Enable paranoid mode (Serpent + XChaCha20, HMAC-SHA3)")
	encryptCmd.Flags().BoolVar(&encReedSolomon, "reed-solomon", false, "Enable Reed-Solomon error correction (6% overhead)")
	encryptCmd.Flags().BoolVar(&encDeniability, "deniability", false, "Add deniability wrapper")
	encryptCmd.Flags().BoolVar(&encCompress, "compress", false, "Compress files before encryption")

	// Split options
	encryptCmd.Flags().BoolVar(&encSplit, "split", false, "Split output into chunks")
	encryptCmd.Flags().IntVar(&encSplitSize, "split-size", 0, "Size of each chunk (requires --split)")
	encryptCmd.Flags().StringVar(&encSplitUnit, "split-unit", "MiB", "Unit for split size: KiB, MiB, GiB, TiB, or Total")

	// Other
	encryptCmd.Flags().BoolVarP(&encQuiet, "quiet", "q", false, "Suppress progress output")
	encryptCmd.Flags().BoolVarP(&encYes, "yes", "y", false, "Overwrite output file without prompting")
	encryptCmd.Flags().BoolVar(&encFollowSymlinks, "follow-symlinks", false, "Follow symlinks to regular files")

	// Mark required
	_ = encryptCmd.MarkFlagRequired("input")
}

func defaultEncryptOutput(rawInput string, allFiles []string, useStdin bool) string {
	if useStdin {
		return "encrypted.pcv"
	}
	if len(allFiles) == 1 {
		return allFiles[0] + ".pcv"
	}
	if len(allFiles) == 0 && rawInput != "" {
		return rawInput + ".pcv"
	}
	return "encrypted.pcv"
}

func runEncrypt(cmd *cobra.Command, args []string) error {
	// Validate inputs
	if len(encInput) == 0 {
		return fmt.Errorf("at least one input file is required (-i)")
	}

	// Check for stdin/stdout
	useStdout := IsStdout(encOutput)

	// Check if any input is stdin
	hasStdinInput := false
	for _, p := range encInput {
		if IsStdin(p) {
			hasStdinInput = true
			break
		}
	}
	useStdin := len(encInput) == 1 && hasStdinInput

	// Validate stdin/stdout constraints
	if hasStdinInput && len(encInput) > 1 {
		return fmt.Errorf("stdin (-i -) cannot be combined with other input files")
	}
	if useStdin && encPasswordStdin {
		return fmt.Errorf("cannot use -P (password from stdin) with -i - (input from stdin)")
	}
	if (useStdin || useStdout) && encSplit {
		return fmt.Errorf("stdin/stdout not compatible with --split")
	}
	if (useStdin || useStdout) && encDeniability {
		return fmt.Errorf("stdin/stdout not compatible with --deniability")
	}

	// Auto-quiet when outputting to stdout (avoid mixing progress with data)
	if useStdout {
		encQuiet = true
	}

	// Track temp files for cleanup
	var stdinTempFile string
	var stdoutTempFile string
	defer func() {
		if stdinTempFile != "" {
			_ = os.Remove(stdinTempFile)
		}
		if stdoutTempFile != "" {
			_ = os.Remove(stdoutTempFile)
		}
	}()

	outputFile := encOutput
	if outputFile == "" && useStdin {
		outputFile = "encrypted.pcv"
	}
	if outputFile != "" && !useStdout && !strings.HasSuffix(outputFile, ".pcv") {
		outputFile += ".pcv"
	}
	if useStdin && !useStdout && !encYes {
		if info, err := os.Stat(outputFile); err == nil {
			if info.IsDir() {
				return fmt.Errorf("output path is a directory: %s", outputFile)
			}
			return fmt.Errorf("output file %s already exists; when reading input from stdin use -y to overwrite", outputFile)
		}
	}

	// Check input files exist
	var allFiles []string
	var onlyFiles []string
	var onlyFolders []string

	// Handle stdin input
	if useStdin {
		var err error
		stdinTempFile, err = BufferStdinToTemp(encOutput)
		if err != nil {
			return fmt.Errorf("buffering stdin: %w", err)
		}
		allFiles = []string{stdinTempFile}
		onlyFiles = []string{stdinTempFile}
	} else {
		for _, input := range encInput {
			// Expand glob patterns
			matches, err := filepath.Glob(input)
			if err != nil {
				return fmt.Errorf("invalid glob pattern %q: %w", input, err)
			}
			if len(matches) == 0 {
				return fmt.Errorf("input file not found: %s", input)
			}

			for _, match := range matches {
				info, err := os.Stat(match)
				if err != nil {
					return fmt.Errorf("cannot access %s: %w", match, err)
				}

				if info.IsDir() {
					onlyFolders = append(onlyFolders, match)
					// Walk directory to get all files
					err := filepath.Walk(match, func(path string, info os.FileInfo, err error) error {
						if err != nil {
							return err
						}
						mode := info.Mode()
						if mode.IsRegular() {
							allFiles = append(allFiles, path)
						} else if encFollowSymlinks && mode&os.ModeSymlink != 0 {
							// Follow symlink if flag set
							target, err := filepath.EvalSymlinks(path)
							if err != nil {
								return nil // skip broken symlinks
							}
							targetInfo, err := os.Stat(target)
							if err != nil || !targetInfo.Mode().IsRegular() {
								return nil // skip symlinks to dirs/special files
							}
							allFiles = append(allFiles, path)
						}
						return nil
					})
					if err != nil {
						return fmt.Errorf("walking directory %s: %w", match, err)
					}
				} else {
					onlyFiles = append(onlyFiles, match)
					allFiles = append(allFiles, match)
				}
			}
		}
	}

	if len(allFiles) == 0 {
		return fmt.Errorf("no files found to encrypt")
	}

	// Determine output file
	outputPreExisted := false
	if useStdout {
		// Create temp file for stdout output
		var err error
		stdoutTempFile, err = CreateTempOutput(0)
		if err != nil {
			return fmt.Errorf("creating temp output: %w", err)
		}
		outputFile = stdoutTempFile
	} else if outputFile == "" {
		// Auto-generate output name
		rawInput := ""
		if len(encInput) > 0 {
			rawInput = encInput[0]
		}
		outputFile = defaultEncryptOutput(rawInput, allFiles, useStdin)
	}

	// Add .pcv extension if missing (not for stdout temp)
	if !useStdout && !strings.HasSuffix(outputFile, ".pcv") {
		outputFile += ".pcv"
	}

	// Check if output exists (skip for stdout)
	if !useStdout {
		if info, err := os.Stat(outputFile); err == nil {
			if info.IsDir() {
				return fmt.Errorf("output path is a directory: %s", outputFile)
			}
			outputPreExisted = true
			if !encYes {
				fmt.Fprintf(os.Stderr, "Output file %s already exists. Overwrite? [y/N]: ", outputFile)
				reader := bufio.NewReader(os.Stdin)
				response, err := reader.ReadString('\n')
				if err != nil && err != io.EOF {
					return fmt.Errorf("reading confirmation: %w", err)
				}
				response = strings.TrimSpace(strings.ToLower(response))
				if response != "y" && response != "yes" {
					return fmt.Errorf("operation cancelled")
				}
			}
		}
	}

	// Get password
	password := encPassword
	if encPasswordStdin {
		var err error
		password, err = ReadPasswordFromStdin()
		if err != nil {
			return err
		}
		if password == "" && len(encKeyfiles) == 0 {
			return fmt.Errorf("password input: %w", ErrPasswordEmpty)
		}
	} else if password == "" {
		// Prompt for password interactively
		// Allow empty password only if keyfiles are provided
		hasKeyfiles := len(encKeyfiles) > 0
		if hasKeyfiles {
			fmt.Fprintln(os.Stderr, "Keyfiles provided. Press Enter for keyfile-only encryption, or enter a password.")
		}
		var err error
		password, err = ReadPasswordInteractive(true, hasKeyfiles) // confirm=true, allowEmpty=hasKeyfiles
		if err != nil {
			return fmt.Errorf("password input: %w", err)
		}
	}

	// Validate keyfiles exist
	for _, kf := range encKeyfiles {
		if _, err := os.Stat(kf); err != nil {
			return fmt.Errorf("keyfile not found: %s", kf)
		}
	}

	// Validate split options
	var chunkSize int
	var chunkUnit fileops.SplitUnit
	if encSplit {
		if encSplitSize <= 0 {
			return fmt.Errorf("--split-size is required when --split is enabled")
		}
		chunkSize = encSplitSize

		switch strings.ToLower(encSplitUnit) {
		case "kib":
			chunkUnit = fileops.SplitUnitKiB
		case "mib":
			chunkUnit = fileops.SplitUnitMiB
		case "gib":
			chunkUnit = fileops.SplitUnitGiB
		case "tib":
			chunkUnit = fileops.SplitUnitTiB
		case "total":
			chunkUnit = fileops.SplitUnitTotal
		default:
			return fmt.Errorf("invalid split unit: %s (must be KiB, MiB, GiB, TiB, or Total)", encSplitUnit)
		}
	}

	// Initialize RS codecs
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		return fmt.Errorf("initializing Reed-Solomon codecs: %w", err)
	}

	// Create reporter
	reporter := NewReporter(encQuiet)
	globalReporter.Store(reporter)

	// Build request
	req := &volume.EncryptRequest{
		InputFiles:     allFiles,
		OnlyFiles:      onlyFiles,
		OnlyFolders:    onlyFolders,
		OutputFile:     outputFile,
		Password:       password,
		Keyfiles:       encKeyfiles,
		KeyfileOrdered: encKeyfileOrder,
		Comments:       encComments,
		Paranoid:       encParanoid,
		ReedSolomon:    encReedSolomon,
		Deniability:    encDeniability,
		Compress:       encCompress,
		Split:          encSplit,
		ChunkSize:      chunkSize,
		ChunkUnit:      chunkUnit,
		Reporter:       reporter,
		RSCodecs:       rsCodecs,
	}

	// Print info
	if !encQuiet {
		destName := outputFile
		if useStdout {
			destName = "stdout"
		}
		srcName := fmt.Sprintf("%d file(s)", len(allFiles))
		if useStdin {
			srcName = "stdin"
		}
		fmt.Fprintf(os.Stderr, "Encrypting %s to %s\n", srcName, destName)
		if encParanoid {
			fmt.Fprintln(os.Stderr, "Mode: Paranoid (Serpent-CTR + XChaCha20, HMAC-SHA3)")
		}
		if encReedSolomon {
			fmt.Fprintln(os.Stderr, "Reed-Solomon: Enabled (6% size overhead)")
		}
		if encDeniability {
			fmt.Fprintln(os.Stderr, "Deniability: Enabled")
		}
		fmt.Fprintln(os.Stderr)
	}

	// Run encryption
	err = volume.Encrypt(context.Background(), req)
	reporter.Finish()

	if err != nil {
		reporter.PrintError("%v", err)
		cleanupEncryptError(outputFile, useStdout, outputPreExisted)
		return err
	}

	// Stream to stdout if requested
	if useStdout {
		if err := StreamFileToStdout(outputFile); err != nil {
			return fmt.Errorf("streaming to stdout: %w", err)
		}
		return nil
	}

	reporter.PrintSuccess("Encryption completed successfully: %s", outputFile)
	return nil
}

func cleanupEncryptError(outputFile string, useStdout, outputPreExisted bool) {
	if useStdout {
		return
	}
	if !outputPreExisted {
		_ = os.Remove(outputFile)
	}
	_ = os.Remove(outputFile + ".incomplete")
}
