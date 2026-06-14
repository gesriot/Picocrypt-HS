// Package volume provides high-level encryption and decryption operations for Picocrypt volumes.
//
// This is AUDIT-CRITICAL code - changes here directly affect the cryptographic pipeline.
// The package orchestrates the complete encryption/decryption workflow:
//
// Encryption pipeline:
//  1. Preprocess: Create zip archive if multiple files or compression requested
//  2. Generate: Create random salts, nonces, IVs
//  3. Write header: RS-encode and write header fields
//  4. Derive keys: Argon2id password derivation
//  5. Process keyfiles: Hash and XOR with password key
//  6. Compute auth: Calculate header HMAC (v2) or key hash (v1)
//  7. Encrypt payload: Serpent-CTR -> XChaCha20 -> MAC
//  8. Finalize: Write auth tag, add deniability wrapper, split chunks
//
// Decryption pipeline:
//  1. Preprocess: Recombine chunks, remove deniability wrapper
//  2. Read header: RS-decode header fields
//  3. Derive keys: Argon2id password derivation
//  4. Process keyfiles: Validate against stored hash
//  5. Verify auth: Check header MAC (v2) or key hash (v1)
//  6. Decrypt payload: MAC -> XChaCha20 -> Serpent-CTR
//  7. Finalize: Verify MAC, auto-unzip if requested
//
// SECURITY: Always call OperationContext.Close() when done to zero key material.
package volume

import (
	"context"
	"io"

	"Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/encoding"
	perrors "Picocrypt-NG/internal/errors"
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/header"
)

// ProgressReporter provides callbacks for UI updates during long-running operations.
// Implementations must be thread-safe as methods may be called from goroutines.
type ProgressReporter interface {
	SetStatus(text string)                     // Update status message (e.g., "Encrypting...")
	SetProgress(fraction float32, info string) // Update progress bar (0.0-1.0) and info text
	SetCanCancel(can bool)                     // Enable/disable cancel button
	Update()                                   // Trigger UI refresh
	IsCancelled() bool                         // Check if user requested cancellation
}

// EncryptRequest contains all parameters needed to encrypt files into a .pcv volume.
// At minimum, either Password or Keyfiles must be provided.
type EncryptRequest struct {
	// Input files - use InputFile for single file, InputFiles for multiple (zipped automatically)
	InputFile   string   // Single file path to encrypt
	InputFiles  []string // Multiple file paths (will be combined into encrypted zip)
	OnlyFolders []string // Folders that were dropped directly (for correct zip path calculation)
	OnlyFiles   []string // Files that were dropped directly (not from folders)
	OutputFile  string   // Output path for the .pcv volume

	// Credentials - at least one required
	//
	// SECURITY (SEC-05): Password is an immutable Go string. Strings cannot be
	// zeroed in place (they are immutable and freely copied/relocated by the GC),
	// so the password and its transient []byte(Password) copy outlive Close().
	// Guaranteed password zeroing is intentionally out of scope (CONCERNS 3.1;
	// ROADMAP "Out of Scope: Guaranteed password zeroing"); only []byte key
	// material derived from it is zeroed.
	Password       string   // User password (processed through Argon2id) — see SECURITY note above
	Keyfiles       []string // Paths to keyfile(s) for additional security
	KeyfileOrdered bool     // If true, keyfile order matters (sequential hash vs XOR)

	// Security options
	Comments    string // Plaintext comments stored in header (NOT encrypted!)
	Paranoid    bool   // Enable paranoid mode: 8 Argon2 passes, Serpent-CTR + XChaCha20, HMAC-SHA3
	ReedSolomon bool   // Enable Reed-Solomon error correction on payload (6% size overhead)
	Deniability bool   // Wrap volume in additional encryption layer for plausible deniability
	Compress    bool   // Use Deflate compression when creating zip archive

	// Output splitting - useful for storage on FAT32 or cloud services with file size limits
	Split     bool              // Enable splitting output into chunks
	ChunkSize int               // Size of each chunk
	ChunkUnit fileops.SplitUnit // Unit for ChunkSize: KiB, MiB, GiB, TiB, or Total (divide into N parts)

	// Progress reporting
	Reporter ProgressReporter // UI callback interface (can be nil for headless operation)

	// Internal - initialized by caller
	RSCodecs *encoding.RSCodecs // Pre-initialized Reed-Solomon codecs
}

// DecryptRequest contains all parameters needed to decrypt a .pcv volume.
// The Password and/or Keyfiles must match those used during encryption.
type DecryptRequest struct {
	// Input/Output paths
	InputFile  string // Path to .pcv volume (or first chunk if split)
	OutputFile string // Destination path for decrypted output

	// Credentials - must match encryption parameters
	//
	// SECURITY (SEC-05): immutable Go string — cannot be zeroed in place (GC +
	// string immutability). Out of scope, same as EncryptRequest.Password above
	// (CONCERNS 3.1; ROADMAP "Out of Scope: Guaranteed password zeroing").
	Password string   // User password — see SECURITY note above
	Keyfiles []string // Keyfile paths (validated against hash stored in header)

	// Decryption options
	ForceDecrypt bool // Continue despite MAC verification failure (may produce corrupted output)
	VerifyFirst  bool // Two-pass mode: verify MAC before decryption (slower but more secure, PCC-004)
	AutoUnzip    bool // Automatically extract if output is a .zip file
	SameLevel    bool // Extract zip contents to same directory as volume (not subdirectory)

	// Volume state (typically detected automatically)
	Recombine   bool // Volume is split into chunks that need recombining first
	Deniability bool // Volume has deniability wrapper that needs removing first

	// Progress reporting
	Reporter ProgressReporter // UI callback interface (can be nil for headless operation)

	// Internal - initialized by caller
	RSCodecs *encoding.RSCodecs // Pre-initialized Reed-Solomon codecs

	// Output - set by Decrypt() after completion
	Kept *bool // If non-nil and ForceDecrypt was used, set to true if file was kept despite MAC failure
}

// OperationContext holds mutable state during encryption/decryption operations.
// This is created at the start of Encrypt()/Decrypt() and passed through all phases.
type OperationContext struct {
	// Context for cancellation and timeouts
	Ctx context.Context

	// File paths
	InputFile  string // Current input file (may change during preprocessing)
	OutputFile string // Final output destination
	TempFile   string // Intermediate file path (zip archive or recombined chunks)

	// Volume header - populated during encryption or read during decryption
	Header *header.VolumeHeader

	// Cryptographic state
	Key           []byte               // Argon2-derived key (possibly XORed with keyfile key)
	KeyfileKey    []byte               // 32-byte key derived from keyfile(s)
	KeyfileHash   []byte               // SHA3-256(KeyfileKey) for verification
	passwordBytes []byte               // KDF input for the current password form being tried (#19)
	SubkeyReader  *crypto.SubkeyReader // HKDF stream for deriving MAC/Serpent subkeys
	CipherSuite   *crypto.CipherSuite  // Initialized cipher suite (XChaCha20 + optional Serpent)

	// Operation flags
	IsLegacyV1   bool                    // True if decrypting a v1.x volume (different HKDF timing)
	UseKeyfiles  bool                    // True if keyfiles were used/required
	Padded       bool                    // True if final chunk needs unpadding (RS mode)
	TempZipInUse bool                    // True if reading from encrypted temp zip
	TempCiphers  *fileops.TempZipCiphers // Ciphers for encrypted temp zip

	// Reed-Solomon retry state (for corrupt file recovery)
	TriedFullRSDecode bool // Prevents infinite retry loop when MAC fails
	Kept              bool // True if ForceDecrypt was used and MAC failed

	// Recombine state - for proper cleanup
	RecombinedFile string // Path to recombined file (separate from TempFile for when deniability changes it)

	// Progress tracking
	Total    int64            // Total bytes to process
	Done     int64            // Bytes processed so far
	Reporter ProgressReporter // UI callback (may be nil)
}

// NewEncryptContext creates a context for encryption operations.
// If ctx is nil, context.Background() is used.
func NewEncryptContext(ctx context.Context, req *EncryptRequest) *OperationContext {
	if ctx == nil {
		ctx = context.Background()
	}
	return &OperationContext{
		Ctx:        ctx,
		OutputFile: req.OutputFile,
		Reporter:   req.Reporter,
	}
}

// NewDecryptContext creates a context for decryption operations.
// If ctx is nil, context.Background() is used.
func NewDecryptContext(ctx context.Context, req *DecryptRequest) *OperationContext {
	if ctx == nil {
		ctx = context.Background()
	}
	return &OperationContext{
		Ctx:        ctx,
		InputFile:  req.InputFile,
		OutputFile: req.OutputFile,
		Reporter:   req.Reporter,
	}
}

// UpdateProgress updates the progress reporter if available
func (ctx *OperationContext) UpdateProgress(fraction float32, info string) {
	if ctx.Reporter != nil {
		ctx.Reporter.SetProgress(fraction, info)
		ctx.Reporter.Update()
	}
}

// SetStatus updates the status reporter if available
func (ctx *OperationContext) SetStatus(status string) {
	if ctx.Reporter != nil {
		ctx.Reporter.SetStatus(status)
		ctx.Reporter.Update()
	}
}

// SetCanCancel updates cancel availability on the reporter if available.
func (ctx *OperationContext) SetCanCancel(can bool) {
	if ctx.Reporter != nil {
		ctx.Reporter.SetCanCancel(can)
		ctx.Reporter.Update()
	}
}

// IsCancelled checks if the operation has been cancelled.
// Returns true if either the context is done or the reporter indicates cancellation.
func (ctx *OperationContext) IsCancelled() bool {
	// Check context cancellation first (standard Go pattern)
	if ctx.Ctx != nil {
		select {
		case <-ctx.Ctx.Done():
			return true
		default:
		}
	}

	// Also check reporter-based cancellation (for UI cancel button)
	if ctx.Reporter != nil {
		return ctx.Reporter.IsCancelled()
	}
	return false
}

// CancellationError returns the appropriate error when cancelled.
// Returns context error if context is done, otherwise returns ErrCancelled.
func (ctx *OperationContext) CancellationError() error {
	if ctx.Ctx != nil {
		select {
		case <-ctx.Ctx.Done():
			return ctx.Ctx.Err()
		default:
		}
	}
	return perrors.ErrCancelled
}

// TempZipReader wraps the input file with decryption if temp zip was used
func (ctx *OperationContext) TempZipReader(r io.Reader) io.Reader {
	if ctx.TempZipInUse && ctx.TempCiphers != nil {
		return fileops.WrapReaderWithCipher(r, ctx.TempCiphers)
	}
	return r
}

// setKey zeros the previous Key backing array before replacing it with k.
//
// SEC-05 / WR-01: mid-operation reassignments of ctx.Key (the v1/v2 keyfile XOR at
// decrypt.go:303/:343 and the full-RS retry re-derive at decryptDeriveKeys:223)
// produce a NEW slice (keyfile.XORWithKey allocates, processor.go:216; Argon2
// re-derive allocates), orphaning the old backing array. OperationContext.Close()
// (the end-of-operation sweep, D-03) structurally cannot reach those predecessors
// because the field has already moved on. Zeroing here closes that window.
//
// Pitfall 1 (self-assign guard): the no-keyfile v1 path does `ctx.Key = key` where
// key IS ctx.Key (same backing array, decrypt.go:303). A naive zero-then-assign
// would wipe the LIVE key and break decryption. The pointer-identity guard
// (&k[0] != &ctx.Key[0]) skips zeroing in that case; the len(k)==0 guard avoids
// indexing an empty slice. Reuses the single crypto.SecureZero primitive (no second
// zeroing primitive — CONVENTIONS).
func (ctx *OperationContext) setKey(k []byte) {
	if ctx.Key != nil && (len(k) == 0 || &k[0] != &ctx.Key[0]) {
		crypto.SecureZero(ctx.Key)
	}
	ctx.Key = k
}

// setKeyfileKey zeros the previous KeyfileKey backing array before replacing it.
// Analogous to setKey: the full-RS retry re-processes keyfiles (decryptProcessKeyfiles:247),
// orphaning the prior keyfile-key buffer that Close() can no longer reach. Same
// pointer-identity self-assign guard.
func (ctx *OperationContext) setKeyfileKey(k []byte) {
	if ctx.KeyfileKey != nil && (len(k) == 0 || &k[0] != &ctx.KeyfileKey[0]) {
		crypto.SecureZero(ctx.KeyfileKey)
	}
	ctx.KeyfileKey = k
}

// setPasswordBytes zeros the previous password byte form before storing the new
// one. The decrypt path sets this per candidate normalization form (#19); the
// winning form is reused by the RS / verify-first re-derivation paths and is
// zeroed by Close. The same pointer-identity self-assign guard as setKey applies.
// (The password also lives in req.Password as an immutable, un-zeroable string —
// see Close's SECURITY note.)
func (ctx *OperationContext) setPasswordBytes(b []byte) {
	if ctx.passwordBytes != nil && (len(b) == 0 || &b[0] != &ctx.passwordBytes[0]) {
		crypto.SecureZero(ctx.passwordBytes)
	}
	ctx.passwordBytes = b
}

// Close securely zeros all sensitive cryptographic material in the context.
// This should be called via defer immediately after creating the context.
//
// SECURITY: Always call Close() when done with an operation to minimize
// the window during which key material is recoverable from memory.
//
// SECURITY (password limitation): Close() zeros only []byte key material. The
// user password lives in immutable Go strings (EncryptRequest.Password /
// DecryptRequest.Password, and their app/state.go counterparts) plus their
// transient []byte(req.Password) copies. Go strings are immutable and freely
// copied/relocated by the garbage collector, so in-place password zeroing is
// impossible — it is intentionally out of scope (CONCERNS 3.1; ROADMAP "Out of
// Scope: Guaranteed password zeroing"). This is an honest, accepted limitation,
// mirroring crypto.SecureZero's own GC/optimization caveat.
func (ctx *OperationContext) Close() {
	if ctx == nil {
		return
	}

	// Zero main key material
	crypto.SecureZeroMultiple(ctx.Key, ctx.KeyfileKey, ctx.KeyfileHash, ctx.passwordBytes)
	ctx.Key = nil
	ctx.KeyfileKey = nil
	ctx.KeyfileHash = nil
	ctx.passwordBytes = nil

	// Close cipher suite (zeros internal key)
	if ctx.CipherSuite != nil {
		ctx.CipherSuite.Close()
		ctx.CipherSuite = nil
	}

	// Clear header auth values
	if ctx.Header != nil {
		crypto.SecureZeroMultiple(ctx.Header.KeyHash, ctx.Header.AuthTag)
		ctx.Header.KeyHash = nil
		ctx.Header.AuthTag = nil
	}

	// Clear SubkeyReader reference (HKDF state)
	ctx.SubkeyReader = nil

	// Close temp zip ciphers (zeros ephemeral key material)
	if ctx.TempCiphers != nil {
		ctx.TempCiphers.Close()
		ctx.TempCiphers = nil
	}
}
