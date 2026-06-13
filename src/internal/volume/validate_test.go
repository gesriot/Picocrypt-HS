package volume

import (
	"os"
	"path/filepath"
	"testing"

	"Picocrypt-NG/internal/errors"
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/header"
)

func TestEncryptRequestValidate(t *testing.T) {
	// Create temp dir for test files
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test content"), 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		req     *EncryptRequest
		wantErr error
	}{
		{
			name:    "no input files",
			req:     &EncryptRequest{},
			wantErr: errors.ErrNoInputFiles,
		},
		{
			name: "no credentials",
			req: &EncryptRequest{
				InputFile:  testFile,
				OutputFile: filepath.Join(tmpDir, "out.pcv"),
			},
			wantErr: errors.ErrNoCredentials,
		},
		{
			name: "no output file",
			req: &EncryptRequest{
				InputFile: testFile,
				Password:  "test",
			},
			wantErr: nil, // Will fail with validation error
		},
		{
			name: "invalid split size",
			req: &EncryptRequest{
				InputFile:  testFile,
				OutputFile: filepath.Join(tmpDir, "out.pcv"),
				Password:   "test",
				Split:      true,
				ChunkSize:  0,
			},
			wantErr: errors.ErrInvalidChunkSize,
		},
		{
			name: "input file not found",
			req: &EncryptRequest{
				InputFile:  "/nonexistent/file.txt",
				OutputFile: filepath.Join(tmpDir, "out.pcv"),
				Password:   "test",
			},
			wantErr: nil, // Will be a FileError
		},
		{
			name: "valid request",
			req: &EncryptRequest{
				InputFile:  testFile,
				OutputFile: filepath.Join(tmpDir, "out.pcv"),
				Password:   "test",
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
		})
	}
}

// TestValidateRejectsOverflowingChunkSize proves the split upper bound: a chunk
// size whose byte product overflows int64 is rejected by Validate with
// errors.ErrChunkSizeTooLarge instead of silently wrapping. Mirrors the QUAL-05
// early-rejection pattern (the wrap would otherwise surface only at the final
// split step, after the volume is already written).
func TestValidateRejectsOverflowingChunkSize(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test content"), 0644); err != nil {
		t.Fatal(err)
	}

	req := &EncryptRequest{
		InputFile:  testFile,
		OutputFile: filepath.Join(tmpDir, "out.pcv"),
		Password:   "test",
		Split:      true,
		ChunkSize:  1 << 23, // 2^23 TiB * 2^40 = 2^63, overflows int64
		ChunkUnit:  fileops.SplitUnitTiB,
	}
	if err := req.Validate(); !errors.Is(err, errors.ErrChunkSizeTooLarge) {
		t.Fatalf("Validate() error = %v, want errors.ErrChunkSizeTooLarge", err)
	}
}

// TestValidateRejectsLongCommentEarly proves QUAL-05: an over-long comment is
// rejected by EncryptRequest.Validate() with errors.ErrCommentTooLong BEFORE any
// Argon2id key derivation runs. A counting spy wraps the deriveVolumeKey seam
// (the Argon2id entry the encrypt pipeline routes through at encrypt.go:220,
// AFTER Validate); the counter must stay 0 because Validate rejects first.
func TestValidateRejectsLongCommentEarly(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test content"), 0644); err != nil {
		t.Fatal(err)
	}

	// Install a counting spy over the deriveVolumeKey seam (override+restore).
	// TestMain already swaps deriveVolumeKey to the fast stub; we wrap that so the
	// counter proves no key derivation happens when Validate rejects early.
	var deriveCalls int
	prevVolumeKey := deriveVolumeKey
	deriveVolumeKey = func(password, salt []byte, paranoid bool) ([]byte, error) {
		deriveCalls++
		return prevVolumeKey(password, salt, paranoid)
	}
	defer func() { deriveVolumeKey = prevVolumeKey }()

	req := &EncryptRequest{
		InputFile:  testFile,
		OutputFile: filepath.Join(tmpDir, "out.pcv"),
		Password:   "test",
		Comments:   string(make([]byte, header.MaxCommentLen+1)), // 1 over the bound
	}

	err := req.Validate()
	if !errors.Is(err, errors.ErrCommentTooLong) {
		t.Fatalf("Validate() error = %v, want errors.ErrCommentTooLong", err)
	}
	if deriveCalls != 0 {
		t.Errorf("deriveVolumeKey called %d times during Validate; want 0 (no Argon2id before rejection)", deriveCalls)
	}
}

func TestDecryptRequestValidate(t *testing.T) {
	// Create temp dir for test files
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.pcv")
	if err := os.WriteFile(testFile, []byte("test content"), 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		req     *DecryptRequest
		wantErr bool
	}{
		{
			name:    "no input file",
			req:     &DecryptRequest{},
			wantErr: true,
		},
		{
			name: "input file not found",
			req: &DecryptRequest{
				InputFile: "/nonexistent/file.pcv",
			},
			wantErr: true,
		},
		{
			name: "no output file",
			req: &DecryptRequest{
				InputFile: testFile,
			},
			wantErr: true,
		},
		{
			name: "valid request",
			req: &DecryptRequest{
				InputFile:  testFile,
				OutputFile: filepath.Join(tmpDir, "out.txt"),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDecryptRequestValidateCredentials(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.pcv")
	if err := os.WriteFile(testFile, []byte("test content"), 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name             string
		req              *DecryptRequest
		keyfilesRequired bool
		wantErr          error
	}{
		{
			name: "no credentials required",
			req: &DecryptRequest{
				InputFile:  testFile,
				OutputFile: filepath.Join(tmpDir, "out.txt"),
			},
			keyfilesRequired: false,
			wantErr:          errors.ErrNoCredentials,
		},
		{
			name: "keyfiles required but not provided",
			req: &DecryptRequest{
				InputFile:  testFile,
				OutputFile: filepath.Join(tmpDir, "out.txt"),
				Password:   "test",
			},
			keyfilesRequired: true,
			wantErr:          nil, // Will be a validation error
		},
		{
			name: "password only valid when no keyfiles required",
			req: &DecryptRequest{
				InputFile:  testFile,
				OutputFile: filepath.Join(tmpDir, "out.txt"),
				Password:   "test",
			},
			keyfilesRequired: false,
			wantErr:          nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.ValidateCredentials(tt.keyfilesRequired)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("ValidateCredentials() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
		})
	}
}

func TestEncryptRequestBuilder(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test content"), 0644); err != nil {
		t.Fatal(err)
	}

	builder := NewEncryptRequestBuilder()
	req, err := builder.
		WithInputFile(testFile).
		WithOutputFile(filepath.Join(tmpDir, "out.pcv")).
		WithPassword("testpassword").
		WithComments("test comment").
		WithParanoidMode(true).
		WithReedSolomon(true).
		Build()

	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if req.InputFile != testFile {
		t.Errorf("InputFile = %v, want %v", req.InputFile, testFile)
	}
	if req.Password != "testpassword" {
		t.Errorf("Password = %v, want testpassword", req.Password)
	}
	if req.Comments != "test comment" {
		t.Errorf("Comments = %v, want 'test comment'", req.Comments)
	}
	if !req.Paranoid {
		t.Error("Paranoid should be true")
	}
	if !req.ReedSolomon {
		t.Error("ReedSolomon should be true")
	}
}

func TestEncryptRequestBuilderValidationError(t *testing.T) {
	builder := NewEncryptRequestBuilder()
	_, err := builder.Build() // No input file, should fail

	if err == nil {
		t.Error("Build() should return error for invalid request")
	}
}

func TestEncryptRequestBuilderUnchecked(t *testing.T) {
	builder := NewEncryptRequestBuilder()
	req := builder.BuildUnchecked() // No validation

	if req == nil {
		t.Error("BuildUnchecked() should return request even if invalid")
	}
}
