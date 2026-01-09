package fileops

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestSplitAndRecombine tests the full cycle of splitting and recombining a file.
func TestSplitAndRecombine(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a test file with known content
	testData := bytes.Repeat([]byte("Hello, Picocrypt! "), 1000) // ~18 KB
	inputPath := filepath.Join(tmpDir, "test.pcv")
	if err := os.WriteFile(inputPath, testData, 0644); err != nil {
		t.Fatalf("Create test file: %v", err)
	}

	// Split into 5 KiB chunks
	chunks, err := Split(SplitOptions{
		InputPath: inputPath,
		ChunkSize: 5,
		Unit:      SplitUnitKiB,
	})
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}

	// Verify we got multiple chunks
	if len(chunks) < 2 {
		t.Errorf("Expected multiple chunks, got %d", len(chunks))
	}

	// Verify chunks exist and have correct names
	for i, chunk := range chunks {
		expectedName := filepath.Join(tmpDir, "test.pcv."+string(rune('0'+i)))
		if chunk != expectedName {
			t.Errorf("Chunk %d: expected %q, got %q", i, expectedName, chunk)
		}
		if _, err := os.Stat(chunk); err != nil {
			t.Errorf("Chunk %d does not exist: %v", i, err)
		}
	}

	t.Logf("Split into %d chunks", len(chunks))

	// Recombine
	recombinedPath := filepath.Join(tmpDir, "recombined.pcv")
	err = Recombine(RecombineOptions{
		InputBase:  inputPath,
		OutputPath: recombinedPath,
	})
	if err != nil {
		t.Fatalf("Recombine failed: %v", err)
	}

	// Verify recombined file matches original
	recombinedData, err := os.ReadFile(recombinedPath)
	if err != nil {
		t.Fatalf("Read recombined file: %v", err)
	}

	if !bytes.Equal(testData, recombinedData) {
		t.Error("Recombined data does not match original")
		t.Logf("Original length: %d, Recombined length: %d", len(testData), len(recombinedData))
	}

	t.Log("Split and recombine cycle successful")
}

// TestSplitUnits tests different split unit types.
func TestSplitUnits(t *testing.T) {
	testCases := []struct {
		name      string
		unit      SplitUnit
		chunkSize int
		dataSize  int
		minChunks int
		maxChunks int
	}{
		{"KiB", SplitUnitKiB, 1, 3 * 1024, 3, 3},             // 3 KiB into 1 KiB chunks = 3 chunks
		{"MiB", SplitUnitMiB, 1, 1024 * 1024, 1, 1},          // 1 MiB into 1 MiB chunks = 1 chunk
		{"Total_3parts", SplitUnitTotal, 3, 9000, 3, 3},      // 9000 bytes into 3 parts
		{"Total_5parts", SplitUnitTotal, 5, 10000, 5, 5},     // 10000 bytes into 5 parts
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()

			// Create test data
			testData := bytes.Repeat([]byte("X"), tc.dataSize)
			inputPath := filepath.Join(tmpDir, "test.dat")
			if err := os.WriteFile(inputPath, testData, 0644); err != nil {
				t.Fatalf("Create test file: %v", err)
			}

			chunks, err := Split(SplitOptions{
				InputPath: inputPath,
				ChunkSize: tc.chunkSize,
				Unit:      tc.unit,
			})
			if err != nil {
				t.Fatalf("Split failed: %v", err)
			}

			if len(chunks) < tc.minChunks || len(chunks) > tc.maxChunks {
				t.Errorf("Expected %d-%d chunks, got %d", tc.minChunks, tc.maxChunks, len(chunks))
			}

			// Verify total size matches
			var totalChunkSize int64
			for _, chunk := range chunks {
				stat, err := os.Stat(chunk)
				if err != nil {
					t.Fatalf("Stat chunk: %v", err)
				}
				totalChunkSize += stat.Size()
			}

			if totalChunkSize != int64(tc.dataSize) {
				t.Errorf("Total chunk size %d != original size %d", totalChunkSize, tc.dataSize)
			}

			t.Logf("Split %d bytes into %d chunks with unit %s", tc.dataSize, len(chunks), tc.name)
		})
	}
}

// TestSplitCancellation tests that split can be cancelled.
func TestSplitCancellation(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a larger test file
	testData := bytes.Repeat([]byte("Data"), 100000) // 400 KB
	inputPath := filepath.Join(tmpDir, "test.dat")
	if err := os.WriteFile(inputPath, testData, 0644); err != nil {
		t.Fatalf("Create test file: %v", err)
	}

	// Cancel immediately
	_, err := Split(SplitOptions{
		InputPath: inputPath,
		ChunkSize: 1,
		Unit:      SplitUnitKiB,
		Cancel:    func() bool { return true },
	})

	if err == nil {
		t.Fatal("Expected cancellation error, got nil")
	}

	if err.Error() != "operation cancelled" {
		t.Errorf("Expected 'operation cancelled' error, got: %v", err)
	}

	// Verify no chunks remain
	chunks, _ := filepath.Glob(inputPath + ".*")
	if len(chunks) > 0 {
		t.Errorf("Expected no chunks after cancellation, found %d", len(chunks))
	}

	t.Log("Split cancellation works correctly")
}

// TestRecombineCancellation tests that recombine can be cancelled.
func TestRecombineCancellation(t *testing.T) {
	tmpDir := t.TempDir()

	// Create chunks manually
	for i := 0; i < 5; i++ {
		chunkData := bytes.Repeat([]byte{byte(i)}, 1000)
		chunkPath := filepath.Join(tmpDir, "test.pcv."+string(rune('0'+i)))
		if err := os.WriteFile(chunkPath, chunkData, 0644); err != nil {
			t.Fatalf("Create chunk: %v", err)
		}
	}

	// Cancel immediately
	err := Recombine(RecombineOptions{
		InputBase:  filepath.Join(tmpDir, "test.pcv"),
		OutputPath: filepath.Join(tmpDir, "output.pcv"),
		Cancel:     func() bool { return true },
	})

	if err == nil {
		t.Fatal("Expected cancellation error, got nil")
	}

	if err.Error() != "operation cancelled" {
		t.Errorf("Expected 'operation cancelled' error, got: %v", err)
	}

	// Verify output file does not exist
	if _, err := os.Stat(filepath.Join(tmpDir, "output.pcv")); !os.IsNotExist(err) {
		t.Error("Expected output file to be removed after cancellation")
	}

	t.Log("Recombine cancellation works correctly")
}

// TestCountChunks tests the chunk counting function.
func TestCountChunks(t *testing.T) {
	tmpDir := t.TempDir()
	basePath := filepath.Join(tmpDir, "test.pcv")

	// No chunks
	count, size, err := CountChunks(basePath)
	if err == nil {
		t.Error("Expected error for no chunks")
	}

	// Create some chunks
	chunkSizes := []int{100, 200, 150}
	for i, sz := range chunkSizes {
		chunkPath := basePath + "." + string(rune('0'+i))
		if err := os.WriteFile(chunkPath, bytes.Repeat([]byte{0}, sz), 0644); err != nil {
			t.Fatalf("Create chunk: %v", err)
		}
	}

	count, size, err = CountChunks(basePath)
	if err != nil {
		t.Fatalf("CountChunks failed: %v", err)
	}

	if count != 3 {
		t.Errorf("Expected 3 chunks, got %d", count)
	}

	expectedSize := int64(100 + 200 + 150)
	if size != expectedSize {
		t.Errorf("Expected total size %d, got %d", expectedSize, size)
	}

	t.Logf("CountChunks: found %d chunks, %d bytes total", count, size)
}

// TestRecombineOutputExists tests that recombine fails if output exists.
func TestRecombineOutputExists(t *testing.T) {
	tmpDir := t.TempDir()
	basePath := filepath.Join(tmpDir, "test.pcv")
	outputPath := filepath.Join(tmpDir, "output.pcv")

	// Create a chunk
	if err := os.WriteFile(basePath+".0", []byte("chunk0"), 0644); err != nil {
		t.Fatalf("Create chunk: %v", err)
	}

	// Create output file
	if err := os.WriteFile(outputPath, []byte("existing"), 0644); err != nil {
		t.Fatalf("Create output file: %v", err)
	}

	err := Recombine(RecombineOptions{
		InputBase:  basePath,
		OutputPath: outputPath,
	})

	if err == nil {
		t.Error("Expected error for existing output file")
	}

	t.Logf("Recombine correctly refuses to overwrite: %v", err)
}

// TestSplitProgress tests that progress callback is called.
func TestSplitProgress(t *testing.T) {
	tmpDir := t.TempDir()

	testData := bytes.Repeat([]byte("X"), 10*1024) // 10 KiB
	inputPath := filepath.Join(tmpDir, "test.dat")
	if err := os.WriteFile(inputPath, testData, 0644); err != nil {
		t.Fatalf("Create test file: %v", err)
	}

	progressCalls := 0
	statusCalls := 0

	_, err := Split(SplitOptions{
		InputPath: inputPath,
		ChunkSize: 1,
		Unit:      SplitUnitKiB,
		Progress: func(p float32, info string) {
			progressCalls++
		},
		Status: func(s string) {
			statusCalls++
		},
	})
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}

	if progressCalls == 0 {
		t.Error("Progress callback was never called")
	}
	if statusCalls == 0 {
		t.Error("Status callback was never called")
	}

	t.Logf("Progress called %d times, Status called %d times", progressCalls, statusCalls)
}
