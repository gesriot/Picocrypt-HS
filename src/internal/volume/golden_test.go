package volume

import (
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/header"
	"archive/zip"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GoldenTestReporter is a minimal reporter for testing
type GoldenTestReporter struct {
	status    string
	cancelled bool
}

func (r *GoldenTestReporter) SetStatus(text string) {
	r.status = text
}

func (r *GoldenTestReporter) SetProgress(fraction float32, info string) {}

func (r *GoldenTestReporter) SetCanCancel(can bool) {}

func (r *GoldenTestReporter) Update() {}

func (r *GoldenTestReporter) IsCancelled() bool {
	return r.cancelled
}

// Test password for all golden files
const goldenPassword = "test"

// Expected plaintext content
const expectedContent = "There is a test file for Picocrypt validation.\n"

const (
	goldenV209Fixture      = "pico_test_v209.txt.pcv"
	goldenV209SourceTag    = "v2.09"
	goldenV209SourceCommit = "1cb431d279e0ec4d712bfcaf2f55c1e951837785"
)

var goldenKeyfileFixtures = []string{
	"keyfile_alpha.bin",
	"keyfile_beta.bin",
	"keyfile_gamma.bin",
}

// Golden test corpus paths (relative to testdata/golden/)
var goldenTestCases = []struct {
	name        string
	file        string
	deniability bool
	paranoid    bool
	reedSolomon bool
}{
	{
		name:        "v1_basic",
		file:        "pico_test_v1.txt.pcv",
		deniability: false,
		paranoid:    false,
		reedSolomon: false,
	},
	{
		name:        "v2_basic",
		file:        "pico_test_v2.txt.pcv",
		deniability: false,
		paranoid:    false,
		reedSolomon: false,
	},
	{
		// Cross-version interop fixture: authored by a stock 2.08 CLI build
		// (not current src). Decrypting it under HEAD proves the on-disk
		// format is frozen across versions (REL-01).
		name:        "v208_basic",
		file:        "pico_test_v208.txt.pcv",
		deniability: false,
		paranoid:    false,
		reedSolomon: false,
	},
	{
		// Cross-version interop fixture: authored by the human-authorized
		// v2.09 tag snapshot, not by the current writer.
		name:        "v209_basic",
		file:        goldenV209Fixture,
		deniability: false,
		paranoid:    false,
		reedSolomon: false,
	},
	{
		name:        "v1_deny_paranoid_rs",
		file:        "pico_test_v1_deny_paranoid_rs.txt.pcv",
		deniability: true,
		paranoid:    true,
		reedSolomon: true,
	},
	{
		name:        "v2_deny_paranoid_rs",
		file:        "pico_test_v2_deny_paranoid_rs.txt.pcv",
		deniability: true,
		paranoid:    true,
		reedSolomon: true,
	},
}

// Golden test corpus for compressed (zip) files
var goldenCompressedTestCases = []struct {
	name        string
	file        string
	deniability bool
	paranoid    bool
	reedSolomon bool
}{
	{
		name:        "v1_compress",
		file:        "pico_test_v1_compress.zip.pcv",
		deniability: false,
		paranoid:    false,
		reedSolomon: false,
	},
	{
		name:        "v2_compress",
		file:        "pico_test_v2_compress.zip.pcv",
		deniability: false,
		paranoid:    false,
		reedSolomon: false,
	},
	{
		name:        "v1_deny_paranoid_rs_compress",
		file:        "pico_test_v1_deny_paranoid_rs_compress.zip.pcv",
		deniability: true,
		paranoid:    true,
		reedSolomon: true,
	},
	{
		name:        "v2_deny_paranoid_rs_compress",
		file:        "pico_test_v2_deny_paranoid_rs_compress.zip.pcv",
		deniability: true,
		paranoid:    true,
		reedSolomon: true,
	},
}

var goldenKeyfileTestCases = []struct {
	name           string
	file           string
	password       string
	keyfiles       []string
	keyfileOrdered bool
}{
	{
		name:           "v2_keyfile_single",
		file:           "pico_test_v2_keyfile_single.txt.pcv",
		password:       goldenPassword,
		keyfiles:       []string{"keyfile_alpha.bin"},
		keyfileOrdered: false,
	},
	{
		name:           "v2_keyfile_only",
		file:           "pico_test_v2_keyfile_only.txt.pcv",
		password:       "",
		keyfiles:       []string{"keyfile_alpha.bin"},
		keyfileOrdered: false,
	},
	{
		name:           "v2_keyfile_multi",
		file:           "pico_test_v2_keyfile_multi.txt.pcv",
		password:       goldenPassword,
		keyfiles:       []string{"keyfile_alpha.bin", "keyfile_beta.bin"},
		keyfileOrdered: false,
	},
	{
		name:           "v2_keyfile_multi_ordered",
		file:           "pico_test_v2_keyfile_multi_ordered.txt.pcv",
		password:       goldenPassword,
		keyfiles:       []string{"keyfile_alpha.bin", "keyfile_beta.bin"},
		keyfileOrdered: true,
	},
}

var goldenCompressedKeyfileTestCases = []struct {
	name           string
	file           string
	password       string
	keyfiles       []string
	keyfileOrdered bool
}{
	{
		name:           "v2_keyfile_compress",
		file:           "pico_test_v2_keyfile_compress.zip.pcv",
		password:       goldenPassword,
		keyfiles:       []string{"keyfile_alpha.bin"},
		keyfileOrdered: false,
	},
}

func TestGoldenKeyfileCorpusPresent(t *testing.T) {
	testdataPath := findTestdata(t)

	required := make([]string, 0, len(goldenKeyfileFixtures)+len(goldenKeyfileTestCases)+len(goldenCompressedKeyfileTestCases))
	required = append(required, goldenKeyfileFixtures...)
	for _, tc := range goldenKeyfileTestCases {
		required = append(required, tc.file)
	}
	for _, tc := range goldenCompressedKeyfileTestCases {
		required = append(required, tc.file)
	}

	for _, name := range required {
		path := filepath.Join(testdataPath, name)
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("required golden asset missing: %s (%v)", path, err)
		}
	}
}

// TestGoldenV208CorpusPresent enforces that the cross-version 2.08 golden
// fixture is REQUIRED (not skippable). REL-01 mandates this fixture as the
// frozen-format interop proof, so its absence must hard-fail rather than let
// the v208_basic case silently skip via the per-case t.Skipf in
// TestGoldenDecryption.
func TestGoldenV208CorpusPresent(t *testing.T) {
	testdataPath := findTestdata(t)
	path := filepath.Join(testdataPath, "pico_test_v208.txt.pcv")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("required golden asset missing: %s (%v)", path, err)
	}
}

func TestGoldenV209CorpusPresent(t *testing.T) {
	testdataPath := findTestdata(t)
	path := filepath.Join(testdataPath, goldenV209Fixture)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("required golden asset missing: %s (%v)", path, err)
	}
}

// TestGoldenBasicCorpusPresent hard-fails if ANY fixture decrypted by
// TestGoldenDecryption / TestGoldenCompressedDecryption is missing. Those suites
// per-case t.Skipf on a missing file, so a deleted/renamed golden would silently
// stop being exercised (a frozen-format regression could pass unnoticed, Rule 12).
// This guard makes their absence a hard CI failure instead.
func TestGoldenBasicCorpusPresent(t *testing.T) {
	testdataPath := findTestdata(t)

	required := make([]string, 0, len(goldenTestCases)+len(goldenCompressedTestCases))
	for _, tc := range goldenTestCases {
		required = append(required, tc.file)
	}
	for _, tc := range goldenCompressedTestCases {
		required = append(required, tc.file)
	}

	for _, name := range required {
		path := filepath.Join(testdataPath, name)
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("required golden asset missing: %s (%v)", path, err)
		}
	}
}

func TestGoldenDecryption(t *testing.T) {
	restore := useProductionTestKDF()
	defer restore()

	// Find the testdata directory
	testdataPath := findTestdata(t)

	// Initialize RS codecs
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	for _, tc := range goldenTestCases {
		t.Run(tc.name, func(t *testing.T) {
			inputPath := filepath.Join(testdataPath, tc.file)

			// Required corpus (TestGoldenBasicCorpusPresent); fail-loud if missing.
			if _, err := os.Stat(inputPath); err != nil {
				t.Fatalf("required golden file missing: %s (%v)", inputPath, err)
			}

			// Create temp output file
			tmpDir := t.TempDir()
			outputPath := filepath.Join(tmpDir, "decrypted.txt")

			// Copy input file to temp (to avoid modifying original during deniability removal)
			workingPath := inputPath
			if tc.deniability {
				workingPath = filepath.Join(tmpDir, tc.file)
				copyFile(t, inputPath, workingPath)
			}

			reporter := &GoldenTestReporter{}

			req := &DecryptRequest{
				InputFile:    workingPath,
				OutputFile:   outputPath,
				Password:     []byte(goldenPassword),
				ForceDecrypt: false,
				AutoUnzip:    false,
				SameLevel:    false,
				Recombine:    false,
				Deniability:  tc.deniability,
				Reporter:     reporter,
				RSCodecs:     rsCodecs,
			}

			err := Decrypt(context.Background(), req)
			if err != nil {
				t.Fatalf("Decrypt failed: %v (status: %s)", err, reporter.status)
			}

			// Verify output exists
			if _, err := os.Stat(outputPath); os.IsNotExist(err) {
				t.Fatal("Output file was not created")
			}

			// Read and verify content
			content, err := os.ReadFile(outputPath)
			if err != nil {
				t.Fatalf("Failed to read output: %v", err)
			}

			if string(content) != expectedContent {
				t.Errorf("Content mismatch.\nExpected: %q\nGot: %q", expectedContent, string(content))
			}

			t.Logf("Successfully decrypted %s", tc.file)
		})
	}
}

// TestGoldenCompressedDecryption tests decrypting compressed (zip) golden files
func TestGoldenCompressedDecryption(t *testing.T) {
	restore := useProductionTestKDF()
	defer restore()

	testdataPath := findTestdata(t)

	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	for _, tc := range goldenCompressedTestCases {
		t.Run(tc.name, func(t *testing.T) {
			inputPath := filepath.Join(testdataPath, tc.file)

			// Required corpus (TestGoldenBasicCorpusPresent); fail-loud if missing.
			if _, err := os.Stat(inputPath); err != nil {
				t.Fatalf("required golden file missing: %s (%v)", inputPath, err)
			}

			tmpDir := t.TempDir()
			outputPath := filepath.Join(tmpDir, strings.TrimSuffix(tc.file, ".pcv"))

			// Copy input file to temp (to avoid modifying original during deniability removal)
			workingPath := inputPath
			if tc.deniability {
				workingPath = filepath.Join(tmpDir, tc.file)
				copyFile(t, inputPath, workingPath)
			}

			reporter := &GoldenTestReporter{}

			req := &DecryptRequest{
				InputFile:    workingPath,
				OutputFile:   outputPath,
				Password:     []byte(goldenPassword),
				ForceDecrypt: false,
				AutoUnzip:    false, // Don't auto-unzip, we'll verify the zip content manually
				SameLevel:    false,
				Recombine:    false,
				Deniability:  tc.deniability,
				Reporter:     reporter,
				RSCodecs:     rsCodecs,
			}

			err := Decrypt(context.Background(), req)
			if err != nil {
				t.Fatalf("Decrypt failed: %v (status: %s)", err, reporter.status)
			}

			// Verify output exists
			if _, err := os.Stat(outputPath); os.IsNotExist(err) {
				t.Fatal("Output file was not created")
			}

			// Verify it's a valid zip file and check contents
			zipReader, err := zip.OpenReader(outputPath)
			if err != nil {
				t.Fatalf("Failed to open zip: %v", err)
			}
			defer func() { _ = zipReader.Close() }()

			// Find and verify the test file inside the zip
			found := false
			for _, f := range zipReader.File {
				// Look for pico_test.txt inside the zip (might be in a folder)
				if strings.HasSuffix(f.Name, "pico_test.txt") {
					found = true
					rc, err := f.Open()
					if err != nil {
						t.Fatalf("Failed to open file in zip: %v", err)
					}
					content, err := io.ReadAll(rc)
					_ = rc.Close()
					if err != nil {
						t.Fatalf("Failed to read file in zip: %v", err)
					}

					if string(content) != expectedContent {
						t.Errorf("Content mismatch in zip.\nExpected: %q\nGot: %q", expectedContent, string(content))
					}
					break
				}
			}

			if !found {
				// List what's in the zip for debugging
				t.Log("Files in zip:")
				for _, f := range zipReader.File {
					t.Logf("  - %s", f.Name)
				}
				t.Error("pico_test.txt not found in zip")
			}

			t.Logf("Successfully decrypted and verified %s", tc.file)
		})
	}
}

func TestGoldenKeyfileDecryption(t *testing.T) {
	restore := useProductionTestKDF()
	defer restore()

	testdataPath := findTestdata(t)

	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	for _, tc := range goldenKeyfileTestCases {
		t.Run(tc.name, func(t *testing.T) {
			inputPath := filepath.Join(testdataPath, tc.file)
			outputPath := filepath.Join(t.TempDir(), "decrypted.txt")

			req := &DecryptRequest{
				InputFile:    inputPath,
				OutputFile:   outputPath,
				Password:     []byte(tc.password),
				Keyfiles:     goldenFixturePaths(testdataPath, tc.keyfiles),
				ForceDecrypt: false,
				AutoUnzip:    false,
				SameLevel:    false,
				Recombine:    false,
				Deniability:  false,
				Reporter:     &GoldenTestReporter{},
				RSCodecs:     rsCodecs,
			}

			if err := Decrypt(context.Background(), req); err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}

			content, err := os.ReadFile(outputPath)
			if err != nil {
				t.Fatalf("Failed to read output: %v", err)
			}
			if string(content) != expectedContent {
				t.Fatalf("Content mismatch.\nExpected: %q\nGot: %q", expectedContent, string(content))
			}
		})
	}
}

func TestGoldenCompressedKeyfileDecryption(t *testing.T) {
	restore := useProductionTestKDF()
	defer restore()

	testdataPath := findTestdata(t)

	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	for _, tc := range goldenCompressedKeyfileTestCases {
		t.Run(tc.name, func(t *testing.T) {
			inputPath := filepath.Join(testdataPath, tc.file)
			outputPath := filepath.Join(t.TempDir(), strings.TrimSuffix(tc.file, ".pcv"))

			req := &DecryptRequest{
				InputFile:    inputPath,
				OutputFile:   outputPath,
				Password:     []byte(tc.password),
				Keyfiles:     goldenFixturePaths(testdataPath, tc.keyfiles),
				ForceDecrypt: false,
				AutoUnzip:    false,
				SameLevel:    false,
				Recombine:    false,
				Deniability:  false,
				Reporter:     &GoldenTestReporter{},
				RSCodecs:     rsCodecs,
			}

			if err := Decrypt(context.Background(), req); err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}

			zipReader, err := zip.OpenReader(outputPath)
			if err != nil {
				t.Fatalf("Failed to open zip: %v", err)
			}
			defer func() { _ = zipReader.Close() }()

			found := false
			for _, f := range zipReader.File {
				if !strings.HasSuffix(f.Name, "pico_test.txt") {
					continue
				}
				found = true
				rc, err := f.Open()
				if err != nil {
					t.Fatalf("Failed to open file in zip: %v", err)
				}
				content, err := io.ReadAll(rc)
				_ = rc.Close()
				if err != nil {
					t.Fatalf("Failed to read file in zip: %v", err)
				}
				if string(content) != expectedContent {
					t.Fatalf("Content mismatch in zip.\nExpected: %q\nGot: %q", expectedContent, string(content))
				}
			}

			if !found {
				t.Fatal("pico_test.txt not found in zip")
			}
		})
	}
}

func TestGoldenKeyfileFailures(t *testing.T) {
	restore := useProductionTestKDF()
	defer restore()

	testdataPath := findTestdata(t)

	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	testCases := []struct {
		name     string
		file     string
		password string
		keyfiles []string
	}{
		{
			name:     "wrong_single_keyfile",
			file:     "pico_test_v2_keyfile_single.txt.pcv",
			password: goldenPassword,
			keyfiles: []string{"keyfile_gamma.bin"},
		},
		{
			name:     "wrong_ordered_keyfile_order",
			file:     "pico_test_v2_keyfile_multi_ordered.txt.pcv",
			password: goldenPassword,
			keyfiles: []string{"keyfile_beta.bin", "keyfile_alpha.bin"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &DecryptRequest{
				InputFile:    filepath.Join(testdataPath, tc.file),
				OutputFile:   filepath.Join(t.TempDir(), "decrypted.txt"),
				Password:     []byte(tc.password),
				Keyfiles:     goldenFixturePaths(testdataPath, tc.keyfiles),
				ForceDecrypt: false,
				AutoUnzip:    false,
				SameLevel:    false,
				Recombine:    false,
				Deniability:  false,
				Reporter:     &GoldenTestReporter{},
				RSCodecs:     rsCodecs,
			}

			if err := Decrypt(context.Background(), req); err == nil {
				t.Fatal("Decrypt should have failed")
			}
		})
	}
}

func TestGoldenKeyfileHeaderFlags(t *testing.T) {
	testdataPath := findTestdata(t)

	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	testCases := []struct {
		file           string
		keyfileOrdered bool
	}{
		{file: "pico_test_v2_keyfile_single.txt.pcv", keyfileOrdered: false},
		{file: "pico_test_v2_keyfile_only.txt.pcv", keyfileOrdered: false},
		{file: "pico_test_v2_keyfile_multi.txt.pcv", keyfileOrdered: false},
		{file: "pico_test_v2_keyfile_multi_ordered.txt.pcv", keyfileOrdered: true},
		{file: "pico_test_v2_keyfile_compress.zip.pcv", keyfileOrdered: false},
	}

	for _, tc := range testCases {
		t.Run(tc.file, func(t *testing.T) {
			fin, err := os.Open(filepath.Join(testdataPath, tc.file))
			if err != nil {
				t.Fatalf("Failed to open golden file: %v", err)
			}
			defer func() { _ = fin.Close() }()

			result, err := NewHeaderReaderForTest(fin, rsCodecs).ReadHeader()
			if err != nil {
				t.Fatalf("Failed to read header: %v", err)
			}

			if !result.Header.Flags.UseKeyfiles {
				t.Fatal("UseKeyfiles flag should be true")
			}
			if result.Header.Flags.KeyfileOrdered != tc.keyfileOrdered {
				t.Fatalf("KeyfileOrdered = %v, want %v", result.Header.Flags.KeyfileOrdered, tc.keyfileOrdered)
			}
		})
	}
}

func TestGoldenV1Detection(t *testing.T) {
	testdataPath := findTestdata(t)

	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	// Test v1 file detection
	v1Path := filepath.Join(testdataPath, "pico_test_v1.txt.pcv")
	if _, err := os.Stat(v1Path); os.IsNotExist(err) {
		t.Skip("v1 golden file not found")
	}

	fin, err := os.Open(v1Path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fin.Close() }()

	// Read version
	versionEnc := make([]byte, 15)
	if _, err := io.ReadFull(fin, versionEnc); err != nil {
		t.Fatalf("Failed to read version header: %v", err)
	}

	versionDec, err := encoding.Decode(rsCodecs.RS5, versionEnc, false)
	if err != nil {
		t.Fatalf("Failed to decode version: %v", err)
	}

	version := string(versionDec)
	t.Logf("V1 file version: %s", version)

	if !strings.HasPrefix(version, "v1") {
		t.Errorf("Expected v1.x version, got: %s", version)
	}
}

func TestGoldenV2Detection(t *testing.T) {
	testdataPath := findTestdata(t)

	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	// Test v2 file detection
	v2Path := filepath.Join(testdataPath, "pico_test_v2.txt.pcv")
	if _, err := os.Stat(v2Path); os.IsNotExist(err) {
		t.Skip("v2 golden file not found")
	}

	fin, err := os.Open(v2Path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fin.Close() }()

	// Read version
	versionEnc := make([]byte, 15)
	if _, err := io.ReadFull(fin, versionEnc); err != nil {
		t.Fatalf("Failed to read version header: %v", err)
	}

	versionDec, err := encoding.Decode(rsCodecs.RS5, versionEnc, false)
	if err != nil {
		t.Fatalf("Failed to decode version: %v", err)
	}

	version := string(versionDec)
	t.Logf("V2 file version: %s", version)

	if !strings.HasPrefix(version, "v2") {
		t.Errorf("Expected v2.x version, got: %s", version)
	}
}

func TestGoldenV209Detection(t *testing.T) {
	testdataPath := findTestdata(t)

	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	path := filepath.Join(testdataPath, goldenV209Fixture)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("required golden asset missing: %s (%v)", path, err)
	}

	fin, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fin.Close() }()

	versionEnc := make([]byte, 15)
	if _, err := io.ReadFull(fin, versionEnc); err != nil {
		t.Fatalf("Failed to read version header: %v", err)
	}

	versionDec, err := encoding.Decode(rsCodecs.RS5, versionEnc, false)
	if err != nil {
		t.Fatalf("Failed to decode version: %v", err)
	}

	version := string(versionDec)
	t.Logf("V2.09 file version: %s (source tag %s %s)", version, goldenV209SourceTag, goldenV209SourceCommit)

	if version != "v2.09" {
		t.Fatalf("Expected v2.09 version, got: %s", version)
	}
}

func TestGoldenDeniabilityDetection(t *testing.T) {
	testdataPath := findTestdata(t)

	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	testCases := []struct {
		file             string
		shouldBeDeniable bool
	}{
		{"pico_test_v1.txt.pcv", false},
		{"pico_test_v2.txt.pcv", false},
		{"pico_test_v1_deny_paranoid_rs.txt.pcv", true},
		{"pico_test_v2_deny_paranoid_rs.txt.pcv", true},
		// Compressed variants
		{"pico_test_v1_compress.zip.pcv", false},
		{"pico_test_v2_compress.zip.pcv", false},
		{"pico_test_v1_deny_paranoid_rs_compress.zip.pcv", true},
		{"pico_test_v2_deny_paranoid_rs_compress.zip.pcv", true},
	}

	for _, tc := range testCases {
		t.Run(tc.file, func(t *testing.T) {
			path := filepath.Join(testdataPath, tc.file)
			if _, err := os.Stat(path); os.IsNotExist(err) {
				t.Skipf("File not found: %s", path)
			}

			isDeniable := IsDeniable(path, rsCodecs)
			if isDeniable != tc.shouldBeDeniable {
				t.Errorf("IsDeniable(%s) = %v, want %v", tc.file, isDeniable, tc.shouldBeDeniable)
			}
		})
	}
}

func TestGoldenWrongPassword(t *testing.T) {
	restore := useProductionTestKDF()
	defer restore()

	testdataPath := findTestdata(t)

	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	v2Path := filepath.Join(testdataPath, "pico_test_v2.txt.pcv")
	if _, err := os.Stat(v2Path); os.IsNotExist(err) {
		t.Skip("v2 golden file not found")
	}

	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "decrypted.txt")

	req := &DecryptRequest{
		InputFile:    v2Path,
		OutputFile:   outputPath,
		Password:     []byte("wrong_password"),
		ForceDecrypt: false,
		AutoUnzip:    false,
		SameLevel:    false,
		Recombine:    false,
		Deniability:  false,
		Reporter:     &GoldenTestReporter{},
		RSCodecs:     rsCodecs,
	}

	err = Decrypt(context.Background(), req)
	if err == nil {
		t.Error("Decrypt should have failed with wrong password")
	} else {
		t.Logf("Expected error: %v", err)
	}

	// Output should not exist
	if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
		t.Error("Output file should not exist after failed decryption")
	}
}

func TestGoldenV1WrongPassword(t *testing.T) {
	restore := useProductionTestKDF()
	defer restore()

	testdataPath := findTestdata(t)

	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	v1Path := filepath.Join(testdataPath, "pico_test_v1.txt.pcv")
	if _, err := os.Stat(v1Path); os.IsNotExist(err) {
		t.Skip("v1 golden file not found")
	}

	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "decrypted.txt")

	req := &DecryptRequest{
		InputFile:    v1Path,
		OutputFile:   outputPath,
		Password:     []byte("wrong_password"),
		ForceDecrypt: false,
		AutoUnzip:    false,
		SameLevel:    false,
		Recombine:    false,
		Deniability:  false,
		Reporter:     &GoldenTestReporter{},
		RSCodecs:     rsCodecs,
	}

	err = Decrypt(context.Background(), req)
	if err == nil {
		t.Error("Decrypt should have failed with wrong password")
	} else {
		t.Logf("Expected error: %v", err)
	}
}

func TestGoldenHeaderParsing(t *testing.T) {
	testdataPath := findTestdata(t)

	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	cases := []struct {
		file          string
		versionPrefix string
	}{
		{"pico_test_v1.txt.pcv", "v1"},
		{"pico_test_v2.txt.pcv", "v2"},
	}

	allZero := func(b []byte) bool {
		for _, x := range b {
			if x != 0 {
				return false
			}
		}
		return true
	}

	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			path := filepath.Join(testdataPath, tc.file)
			if _, err := os.Stat(path); os.IsNotExist(err) {
				t.Skipf("File not found: %s", path)
			}

			fin, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = fin.Close() }()

			reader := NewHeaderReaderForTest(fin, rsCodecs)
			result, err := reader.ReadHeader()
			if err != nil {
				t.Fatalf("ReadHeader: %v", err)
			}
			// A clean golden fixture must decode without RS errors.
			if result.DecodeError != nil {
				t.Errorf("clean golden fixture decoded with errors: %v", result.DecodeError)
			}

			h := result.Header
			// Version must be a well-formed Picocrypt version of the expected generation.
			if !header.MatchVersion([]byte(h.Version)) {
				t.Errorf("Version %q is not a well-formed Picocrypt version", h.Version)
			}
			if !strings.HasPrefix(h.Version, tc.versionPrefix) {
				t.Errorf("Version = %q; want %s.x", h.Version, tc.versionPrefix)
			}

			// Each crypto field must decode to its fixed width.
			for _, f := range []struct {
				name string
				got  int
				want int
			}{
				{"Salt", len(h.Salt), header.SaltSize},
				{"HKDFSalt", len(h.HKDFSalt), header.HKDFSaltSize},
				{"SerpentIV", len(h.SerpentIV), header.SerpentIVSize},
				{"Nonce", len(h.Nonce), header.NonceSize},
				{"KeyHash", len(h.KeyHash), header.KeyHashSize},
				{"KeyfileHash", len(h.KeyfileHash), header.KeyfileHashSize},
				{"AuthTag", len(h.AuthTag), header.AuthTagSize},
			} {
				if f.got != f.want {
					t.Errorf("%s length = %d; want %d", f.name, f.got, f.want)
				}
			}

			// KeyHash is the password-verification field present in both v1 and v2;
			// an all-zero value would mean the header was mis-decoded.
			if allZero(h.KeyHash) {
				t.Error("KeyHash decoded to all zeros (mis-parsed header)")
			}
		})
	}
}

// Helper functions

func findTestdata(t *testing.T) string {
	// Try various relative paths from test location
	candidates := []string{
		"../../testdata/golden",
		"../testdata/golden",
		"testdata/golden",
		"src/testdata/golden",
	}

	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			absPath, _ := filepath.Abs(c)
			return absPath
		}
	}

	// Try from workspace root
	if wd, err := os.Getwd(); err == nil {
		for _, c := range candidates {
			path := filepath.Join(wd, c)
			if _, err := os.Stat(path); err == nil {
				return path
			}
		}
	}

	t.Fatal("Could not find testdata/golden directory")
	return ""
}

func copyFile(t *testing.T, src, dst string) {
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("Failed to read source file: %v", err)
	}
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		t.Fatalf("Failed to write destination file: %v", err)
	}
}

func goldenFixturePaths(testdataPath string, names []string) []string {
	paths := make([]string, len(names))
	for i, name := range names {
		paths[i] = filepath.Join(testdataPath, name)
	}
	return paths
}

// NewHeaderReaderForTest returns the production header reader so golden tests
// exercise the real, audited parser (with its D-02 comment-length bound and RS
// field widths) instead of a hand-rolled copy that could silently drift from it.
func NewHeaderReaderForTest(r io.Reader, rs *encoding.RSCodecs) *header.Reader {
	return header.NewReader(r, rs)
}
