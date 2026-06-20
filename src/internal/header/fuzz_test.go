package header

import (
	"Picocrypt-NG/internal/encoding"
	"bytes"
	"testing"
)

// FuzzHeaderRead tests header parsing with arbitrary input to ensure robustness.
// The parser should handle corrupted/malformed headers gracefully without panics.
// Run with: go test -fuzz=FuzzHeaderRead -fuzztime=60s
func FuzzHeaderRead(f *testing.F) {
	codecs, err := encoding.NewRSCodecs()
	if err != nil {
		f.Fatal(err)
	}

	// Seed with valid header data
	validHeader := &VolumeHeader{
		Version:  "v2.00",
		Comments: "test comment",
		Flags: Flags{
			Paranoid:       true,
			UseKeyfiles:    false,
			KeyfileOrdered: false,
			ReedSolomon:    true,
			Padded:         false,
		},
		Salt:        make([]byte, SaltSize),
		HKDFSalt:    make([]byte, HKDFSaltSize),
		SerpentIV:   make([]byte, SerpentIVSize),
		Nonce:       make([]byte, NonceSize),
		KeyHash:     make([]byte, KeyHashSize),
		KeyfileHash: make([]byte, KeyfileHashSize),
		AuthTag:     make([]byte, AuthTagSize),
	}

	var buf bytes.Buffer
	writer := NewWriter(&buf, codecs)
	_, _ = writer.WriteHeader(validHeader)
	f.Add(buf.Bytes())

	// Also add truncated versions
	fullData := buf.Bytes()
	for i := 10; i < len(fullData) && i < 200; i += 20 {
		f.Add(fullData[:i])
	}

	// Add random noise
	f.Add(make([]byte, 100))
	f.Add(make([]byte, 500))
	f.Add([]byte("not a valid header at all"))

	f.Fuzz(func(t *testing.T, data []byte) {
		reader := NewReader(bytes.NewReader(data), codecs)

		// ReadHeader should not panic regardless of input
		// It may return an error, which is expected for malformed data
		_, _ = reader.ReadHeader()
	})
}
