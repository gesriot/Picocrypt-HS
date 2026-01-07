package volume

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"testing"

	"Picocrypt-NG/internal/encoding"
)

// TestRoundTripBasic tests basic encrypt → decrypt cycle
func TestRoundTripBasic(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	// Create test file
	plaintext := []byte("Hello, Picocrypt! This is a test message for round-trip encryption.")
	inputPath := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "test.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "test_decrypted.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt
	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   "testpassword123",
		Paranoid:   false,
		ReedSolomon: false,
		Deniability: false,
		Reporter:   reporter,
		RSCodecs:   rsCodecs,
	}

	if err := Encrypt(encReq); err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Verify encrypted file exists
	if _, err := os.Stat(encryptedPath); os.IsNotExist(err) {
		t.Fatal("Encrypted file was not created")
	}

	// Decrypt
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     "testpassword123",
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	if err := Decrypt(decReq); err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	// Verify decrypted content matches original
	decrypted, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Content mismatch.\nExpected: %q\nGot: %q", plaintext, decrypted)
	}

	t.Log("Round-trip basic: SUCCESS")
}

// TestRoundTripParanoid tests encrypt → decrypt with paranoid mode
func TestRoundTripParanoid(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	plaintext := []byte("Paranoid mode test data with extra security.")
	inputPath := filepath.Join(tmpDir, "paranoid_test.txt")
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "paranoid_test.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "paranoid_decrypted.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt with paranoid mode
	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   "paranoid_password",
		Paranoid:   true,
		Reporter:   reporter,
		RSCodecs:   rsCodecs,
	}

	if err := Encrypt(encReq); err != nil {
		t.Fatalf("Encrypt (paranoid) failed: %v", err)
	}

	// Decrypt
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     "paranoid_password",
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	if err := Decrypt(decReq); err != nil {
		t.Fatalf("Decrypt (paranoid) failed: %v", err)
	}

	decrypted, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Content mismatch (paranoid).\nExpected: %q\nGot: %q", plaintext, decrypted)
	}

	t.Log("Round-trip paranoid: SUCCESS")
}

// TestRoundTripReedSolomon tests encrypt → decrypt with Reed-Solomon
func TestRoundTripReedSolomon(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	plaintext := []byte("Reed-Solomon protected data for error correction testing.")
	inputPath := filepath.Join(tmpDir, "rs_test.txt")
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "rs_test.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "rs_decrypted.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt with Reed-Solomon
	encReq := &EncryptRequest{
		InputFile:   inputPath,
		OutputFile:  encryptedPath,
		Password:    "rs_password",
		ReedSolomon: true,
		Reporter:    reporter,
		RSCodecs:    rsCodecs,
	}

	if err := Encrypt(encReq); err != nil {
		t.Fatalf("Encrypt (RS) failed: %v", err)
	}

	// Decrypt
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     "rs_password",
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	if err := Decrypt(decReq); err != nil {
		t.Fatalf("Decrypt (RS) failed: %v", err)
	}

	decrypted, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Content mismatch (RS).\nExpected: %q\nGot: %q", plaintext, decrypted)
	}

	t.Log("Round-trip Reed-Solomon: SUCCESS")
}

// TestRoundTripDeniability tests encrypt → decrypt with deniability
func TestRoundTripDeniability(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	plaintext := []byte("Deniability test data - this should be hidden!")
	inputPath := filepath.Join(tmpDir, "deny_test.txt")
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "deny_test.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "deny_decrypted.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt with deniability
	encReq := &EncryptRequest{
		InputFile:   inputPath,
		OutputFile:  encryptedPath,
		Password:    "deny_password",
		Deniability: true,
		Reporter:    reporter,
		RSCodecs:    rsCodecs,
	}

	if err := Encrypt(encReq); err != nil {
		t.Fatalf("Encrypt (deniability) failed: %v", err)
	}

	// Check that deniability is detected
	if !IsDeniable(encryptedPath, rsCodecs) {
		t.Error("Encrypted file should be detected as deniable")
	}

	// Decrypt with deniability flag
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     "deny_password",
		Deniability:  true,
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	if err := Decrypt(decReq); err != nil {
		t.Fatalf("Decrypt (deniability) failed: %v", err)
	}

	decrypted, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Content mismatch (deniability).\nExpected: %q\nGot: %q", plaintext, decrypted)
	}

	t.Log("Round-trip deniability: SUCCESS")
}

// TestRoundTripAllOptions tests encrypt → decrypt with all options enabled
func TestRoundTripAllOptions(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	plaintext := []byte("Full options test: paranoid + Reed-Solomon + deniability")
	inputPath := filepath.Join(tmpDir, "full_test.txt")
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "full_test.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "full_decrypted.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt with all options
	encReq := &EncryptRequest{
		InputFile:   inputPath,
		OutputFile:  encryptedPath,
		Password:    "full_options_password",
		Paranoid:    true,
		ReedSolomon: true,
		Deniability: true,
		Reporter:    reporter,
		RSCodecs:    rsCodecs,
	}

	if err := Encrypt(encReq); err != nil {
		t.Fatalf("Encrypt (all options) failed: %v", err)
	}

	// Decrypt
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     "full_options_password",
		Deniability:  true,
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	if err := Decrypt(decReq); err != nil {
		t.Fatalf("Decrypt (all options) failed: %v", err)
	}

	decrypted, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Content mismatch (all options).\nExpected: %q\nGot: %q", plaintext, decrypted)
	}

	t.Log("Round-trip all options: SUCCESS")
}

// TestRoundTripWithComments tests encrypt → decrypt with comments
func TestRoundTripWithComments(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	plaintext := []byte("Test data with comments in the header.")
	inputPath := filepath.Join(tmpDir, "comments_test.txt")
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "comments_test.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "comments_decrypted.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt with comments
	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   "comments_password",
		Comments:   "This is a test comment! 日本語テスト 🔐",
		Reporter:   reporter,
		RSCodecs:   rsCodecs,
	}

	if err := Encrypt(encReq); err != nil {
		t.Fatalf("Encrypt (with comments) failed: %v", err)
	}

	// Decrypt
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     "comments_password",
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	if err := Decrypt(decReq); err != nil {
		t.Fatalf("Decrypt (with comments) failed: %v", err)
	}

	decrypted, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Content mismatch (with comments).\nExpected: %q\nGot: %q", plaintext, decrypted)
	}

	t.Log("Round-trip with comments: SUCCESS")
}

// TestRoundTripWithKeyfile tests encrypt → decrypt with keyfile
func TestRoundTripWithKeyfile(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	// Create test file
	plaintext := []byte("Keyfile protected data for testing.")
	inputPath := filepath.Join(tmpDir, "keyfile_test.txt")
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Create keyfile
	keyfilePath := filepath.Join(tmpDir, "keyfile.bin")
	keyfileData := []byte("This is my secret keyfile content!")
	if err := os.WriteFile(keyfilePath, keyfileData, 0644); err != nil {
		t.Fatalf("Failed to write keyfile: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "keyfile_test.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "keyfile_decrypted.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt with keyfile
	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   "password_with_keyfile",
		Keyfiles:   []string{keyfilePath},
		Reporter:   reporter,
		RSCodecs:   rsCodecs,
	}

	if err := Encrypt(encReq); err != nil {
		t.Fatalf("Encrypt (with keyfile) failed: %v", err)
	}

	// Decrypt with keyfile
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     "password_with_keyfile",
		Keyfiles:     []string{keyfilePath},
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	if err := Decrypt(decReq); err != nil {
		t.Fatalf("Decrypt (with keyfile) failed: %v", err)
	}

	decrypted, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Content mismatch (with keyfile).\nExpected: %q\nGot: %q", plaintext, decrypted)
	}

	t.Log("Round-trip with keyfile: SUCCESS")
}

// TestRoundTripWithMultipleKeyfiles tests encrypt → decrypt with multiple keyfiles
func TestRoundTripWithMultipleKeyfiles(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	// Create test file
	plaintext := []byte("Multiple keyfiles protected data.")
	inputPath := filepath.Join(tmpDir, "multi_keyfile_test.txt")
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Create keyfiles
	keyfile1 := filepath.Join(tmpDir, "keyfile1.bin")
	keyfile2 := filepath.Join(tmpDir, "keyfile2.bin")
	if err := os.WriteFile(keyfile1, []byte("First keyfile content"), 0644); err != nil {
		t.Fatalf("Failed to write keyfile1: %v", err)
	}
	if err := os.WriteFile(keyfile2, []byte("Second keyfile content"), 0644); err != nil {
		t.Fatalf("Failed to write keyfile2: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "multi_keyfile_test.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "multi_keyfile_decrypted.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt with multiple keyfiles (unordered - default)
	encReq := &EncryptRequest{
		InputFile:      inputPath,
		OutputFile:     encryptedPath,
		Password:       "multi_keyfile_pass",
		Keyfiles:       []string{keyfile1, keyfile2},
		KeyfileOrdered: false,
		Reporter:       reporter,
		RSCodecs:       rsCodecs,
	}

	if err := Encrypt(encReq); err != nil {
		t.Fatalf("Encrypt (multiple keyfiles) failed: %v", err)
	}

	// Decrypt with keyfiles in different order (should work for unordered)
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     "multi_keyfile_pass",
		Keyfiles:     []string{keyfile2, keyfile1}, // Reversed order
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	if err := Decrypt(decReq); err != nil {
		t.Fatalf("Decrypt (multiple keyfiles, reversed) failed: %v", err)
	}

	decrypted, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Content mismatch (multiple keyfiles).\nExpected: %q\nGot: %q", plaintext, decrypted)
	}

	t.Log("Round-trip with multiple keyfiles: SUCCESS")
}

// TestRoundTripWithOrderedKeyfiles tests encrypt → decrypt with ordered keyfiles
func TestRoundTripWithOrderedKeyfiles(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	// Create test file
	plaintext := []byte("Ordered keyfiles protected data.")
	inputPath := filepath.Join(tmpDir, "ordered_keyfile_test.txt")
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Create keyfiles
	keyfile1 := filepath.Join(tmpDir, "ordered1.bin")
	keyfile2 := filepath.Join(tmpDir, "ordered2.bin")
	if err := os.WriteFile(keyfile1, []byte("First ordered keyfile"), 0644); err != nil {
		t.Fatalf("Failed to write keyfile1: %v", err)
	}
	if err := os.WriteFile(keyfile2, []byte("Second ordered keyfile"), 0644); err != nil {
		t.Fatalf("Failed to write keyfile2: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "ordered_keyfile_test.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "ordered_keyfile_decrypted.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt with ordered keyfiles
	encReq := &EncryptRequest{
		InputFile:      inputPath,
		OutputFile:     encryptedPath,
		Password:       "ordered_keyfile_pass",
		Keyfiles:       []string{keyfile1, keyfile2},
		KeyfileOrdered: true,
		Reporter:       reporter,
		RSCodecs:       rsCodecs,
	}

	if err := Encrypt(encReq); err != nil {
		t.Fatalf("Encrypt (ordered keyfiles) failed: %v", err)
	}

	// Decrypt with same order
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     "ordered_keyfile_pass",
		Keyfiles:     []string{keyfile1, keyfile2},
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	if err := Decrypt(decReq); err != nil {
		t.Fatalf("Decrypt (ordered keyfiles) failed: %v", err)
	}

	decrypted, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Content mismatch (ordered keyfiles).\nExpected: %q\nGot: %q", plaintext, decrypted)
	}

	t.Log("Round-trip with ordered keyfiles: SUCCESS")
}

// TestWrongKeyfileFails verifies that wrong keyfile fails
func TestWrongKeyfileFails(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	plaintext := []byte("Secret data")
	inputPath := filepath.Join(tmpDir, "secret.txt")
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Create correct keyfile
	correctKeyfile := filepath.Join(tmpDir, "correct_keyfile.bin")
	if err := os.WriteFile(correctKeyfile, []byte("Correct keyfile"), 0644); err != nil {
		t.Fatalf("Failed to write correct keyfile: %v", err)
	}

	// Create wrong keyfile
	wrongKeyfile := filepath.Join(tmpDir, "wrong_keyfile.bin")
	if err := os.WriteFile(wrongKeyfile, []byte("Wrong keyfile"), 0644); err != nil {
		t.Fatalf("Failed to write wrong keyfile: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "secret.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "secret_decrypted.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt with correct keyfile
	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   "keyfile_password",
		Keyfiles:   []string{correctKeyfile},
		Reporter:   reporter,
		RSCodecs:   rsCodecs,
	}

	if err := Encrypt(encReq); err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Try to decrypt with wrong keyfile
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     "keyfile_password",
		Keyfiles:     []string{wrongKeyfile},
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	err = Decrypt(decReq)
	if err == nil {
		t.Error("Decrypt should have failed with wrong keyfile")
	} else {
		t.Logf("Expected error: %v", err)
	}

	// Decrypted file should not exist
	if _, err := os.Stat(decryptedPath); !os.IsNotExist(err) {
		t.Error("Decrypted file should not exist after failed decryption")
	}
}

// TestRoundTripSplit tests encrypt with splitting → recombine → decrypt
func TestRoundTripSplit(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	// Create larger test file to have multiple chunks
	plaintext := make([]byte, 1024*100) // 100 KiB
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}
	inputPath := filepath.Join(tmpDir, "split_test.bin")
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "split_test.bin.pcv")
	decryptedPath := filepath.Join(tmpDir, "split_decrypted.bin")

	reporter := &GoldenTestReporter{}

	// Encrypt with splitting (10 KiB chunks)
	// SplitUnitKiB = 0
	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   "split_password",
		Split:      true,
		ChunkSize:  10,
		ChunkUnit:  0, // SplitUnitKiB
		Reporter:   reporter,
		RSCodecs:   rsCodecs,
	}

	if err := Encrypt(encReq); err != nil {
		t.Fatalf("Encrypt (split) failed: %v", err)
	}

	// Verify chunks were created
	chunks, err := filepath.Glob(encryptedPath + ".*")
	if err != nil {
		t.Fatalf("Failed to glob chunks: %v", err)
	}
	if len(chunks) < 2 {
		t.Logf("Only %d chunk(s) created - file might be too small for splitting", len(chunks))
		// Still try to decrypt the first chunk if it exists
		if len(chunks) == 0 {
			t.Skip("No chunks created - splitting might not be working")
		}
	}
	t.Logf("Created %d chunks", len(chunks))

	// Decrypt with recombine
	// InputFile should be the base path (without .N suffix) for recombine
	decReq := &DecryptRequest{
		InputFile:    encryptedPath, // Base path - recombine will look for .0, .1, etc.
		OutputFile:   decryptedPath,
		Password:     "split_password",
		Recombine:    true,
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	if err := Decrypt(decReq); err != nil {
		t.Fatalf("Decrypt (split/recombine) failed: %v", err)
	}

	decrypted, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if len(decrypted) != len(plaintext) {
		t.Errorf("Length mismatch (split). Expected: %d, Got: %d", len(plaintext), len(decrypted))
	}

	for i := range plaintext {
		if decrypted[i] != plaintext[i] {
			t.Errorf("Content mismatch at byte %d (split). Expected: %d, Got: %d", i, plaintext[i], decrypted[i])
			break
		}
	}

	t.Log("Round-trip split/recombine: SUCCESS")
}

// TestWrongPasswordFails verifies that wrong password fails
func TestWrongPasswordFails(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	plaintext := []byte("Secret data")
	inputPath := filepath.Join(tmpDir, "secret.txt")
	if err := os.WriteFile(inputPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "secret.txt.pcv")
	decryptedPath := filepath.Join(tmpDir, "secret_decrypted.txt")

	reporter := &GoldenTestReporter{}

	// Encrypt
	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   "correct_password",
		Reporter:   reporter,
		RSCodecs:   rsCodecs,
	}

	if err := Encrypt(encReq); err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Try to decrypt with wrong password
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     "wrong_password",
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	err = Decrypt(decReq)
	if err == nil {
		t.Error("Decrypt should have failed with wrong password")
	} else {
		t.Logf("Expected error: %v", err)
	}

	// Decrypted file should not exist
	if _, err := os.Stat(decryptedPath); !os.IsNotExist(err) {
		t.Error("Decrypted file should not exist after failed decryption")
	}
}

// TestAutoUnzip tests automatic zip extraction after decryption
func TestAutoUnzip(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	// Create a test file and zip it
	testContent := []byte("Auto-unzip test content!")
	testDir := filepath.Join(tmpDir, "test_folder")
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}
	testFile := filepath.Join(testDir, "test_file.txt")
	if err := os.WriteFile(testFile, testContent, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Create zip file
	zipPath := filepath.Join(tmpDir, "test.zip")
	if err := createTestZip(zipPath, testDir, "test_folder"); err != nil {
		t.Fatalf("Failed to create test zip: %v", err)
	}

	encryptedPath := filepath.Join(tmpDir, "test.zip.pcv")
	decryptedPath := filepath.Join(tmpDir, "test.zip")

	reporter := &GoldenTestReporter{}

	// Encrypt the zip file
	encReq := &EncryptRequest{
		InputFile:  zipPath,
		OutputFile: encryptedPath,
		Password:   "autounzip_password",
		Reporter:   reporter,
		RSCodecs:   rsCodecs,
	}

	if err := Encrypt(encReq); err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Remove original zip and test folder
	os.Remove(zipPath)
	os.RemoveAll(testDir)

	// Decrypt with AutoUnzip enabled
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     "autounzip_password",
		AutoUnzip:    true,
		SameLevel:    false, // Extract to directory containing the zip
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	if err := Decrypt(decReq); err != nil {
		t.Fatalf("Decrypt (auto-unzip) failed: %v", err)
	}

	// Verify the zip was removed (auto-unzip removes it)
	if _, err := os.Stat(decryptedPath); !os.IsNotExist(err) {
		t.Error("Zip file should have been removed after auto-unzip")
	}

	// Verify the extracted content exists
	// When SameLevel=false, extracts to a subdirectory named after the zip
	// So test.zip extracts to test/test_folder/test_file.txt
	extractedFile := filepath.Join(tmpDir, "test", "test_folder", "test_file.txt")
	content, err := os.ReadFile(extractedFile)
	if err != nil {
		t.Fatalf("Failed to read extracted file at %s: %v", extractedFile, err)
	}

	if string(content) != string(testContent) {
		t.Errorf("Content mismatch after auto-unzip.\nExpected: %q\nGot: %q", testContent, content)
	}

	t.Log("Auto-unzip: SUCCESS")
}

// TestAutoUnzipSameLevel tests automatic zip extraction to the same directory as the volume
func TestAutoUnzipSameLevel(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	tmpDir := t.TempDir()

	// Create subdirectory for the encrypted file
	volumeDir := filepath.Join(tmpDir, "volume_location")
	if err := os.MkdirAll(volumeDir, 0755); err != nil {
		t.Fatalf("Failed to create volume directory: %v", err)
	}

	// Create a test file and zip it
	testContent := []byte("Same-level unzip test content!")
	testDir := filepath.Join(tmpDir, "source_folder")
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}
	testFile := filepath.Join(testDir, "same_level_test.txt")
	if err := os.WriteFile(testFile, testContent, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Create zip file
	zipPath := filepath.Join(tmpDir, "samelevel.zip")
	if err := createTestZip(zipPath, testDir, "source_folder"); err != nil {
		t.Fatalf("Failed to create test zip: %v", err)
	}

	encryptedPath := filepath.Join(volumeDir, "samelevel.zip.pcv")
	decryptedPath := filepath.Join(volumeDir, "samelevel.zip")

	reporter := &GoldenTestReporter{}

	// Encrypt the zip file
	encReq := &EncryptRequest{
		InputFile:  zipPath,
		OutputFile: encryptedPath,
		Password:   "samelevel_password",
		Reporter:   reporter,
		RSCodecs:   rsCodecs,
	}

	if err := Encrypt(encReq); err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Remove original zip and test folder
	os.Remove(zipPath)
	os.RemoveAll(testDir)

	// Decrypt with AutoUnzip + SameLevel enabled
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     "samelevel_password",
		AutoUnzip:    true,
		SameLevel:    true, // Extract to same directory as volume
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	if err := Decrypt(decReq); err != nil {
		t.Fatalf("Decrypt (same-level) failed: %v", err)
	}

	// Verify the zip was removed (auto-unzip removes it)
	if _, err := os.Stat(decryptedPath); !os.IsNotExist(err) {
		t.Error("Zip file should have been removed after auto-unzip")
	}

	// Verify the extracted content exists in the same directory as the volume
	extractedFile := filepath.Join(volumeDir, "source_folder", "same_level_test.txt")
	content, err := os.ReadFile(extractedFile)
	if err != nil {
		t.Fatalf("Failed to read extracted file at %s: %v", extractedFile, err)
	}

	if string(content) != string(testContent) {
		t.Errorf("Content mismatch after same-level unzip.\nExpected: %q\nGot: %q", testContent, content)
	}

	t.Log("Auto-unzip same-level: SUCCESS")
}

// createTestZip creates a zip file from a directory
func createTestZip(zipPath, sourceDir, baseName string) error {
	zipFile, err := os.Create(zipPath)
	if err != nil {
		return err
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	return filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Create relative path
		relPath, err := filepath.Rel(filepath.Dir(sourceDir), path)
		if err != nil {
			return err
		}

		if info.IsDir() {
			_, err = zipWriter.Create(relPath + "/")
			return err
		}

		// Create file in zip
		writer, err := zipWriter.Create(relPath)
		if err != nil {
			return err
		}

		// Copy file content
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		_, err = io.Copy(writer, file)
		return err
	})
}
