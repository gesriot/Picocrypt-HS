package volume

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/encoding"
	perrors "Picocrypt-NG/internal/errors"
	"Picocrypt-NG/internal/header"
	"Picocrypt-NG/internal/keyfile"
	"Picocrypt-NG/internal/util"
)

// dupWarnReporter is a minimal ProgressReporter that records whether it ever
// observed a "duplicate" status. The DATA-02 warn-only fix emits
// ctx.SetStatus("Warning: duplicate keyfiles detected (keys cancel out)…") on
// the v1 decrypt path; a seen-duplicate signal proves the warning actually
// fired (guards against a vacuous test where the volume decrypts but no warning
// is surfaced). Mirrors repairingReporter in rs_corruption_test.go.
type dupWarnReporter struct {
	sawDuplicate bool
	cancelled    bool
}

func (r *dupWarnReporter) SetStatus(text string) {
	if strings.Contains(strings.ToLower(text), "duplicate") {
		r.sawDuplicate = true
	}
}

func (r *dupWarnReporter) SetProgress(fraction float32, info string) {}

func (r *dupWarnReporter) SetCanCancel(can bool) {}

func (r *dupWarnReporter) Update() {}

func (r *dupWarnReporter) IsCancelled() bool {
	return r.cancelled
}

// synthesizeV1DupKeyfileVolume writes a real v1-layout .pcv (Version "v1.49")
// authored with an even-count duplicate keyfile set whose unordered XOR cancels
// to an all-zeros keyfile key. It returns the volume path and the duplicate
// keyfile paths to decrypt with.
//
// NG-encrypt cannot author this: it only writes v2 (header.CurrentVersion) AND
// blocks duplicate keyfiles pre-write (encrypt.go:275-277). So the volume is
// assembled here from the real crypto/keyfile/header primitives, mirroring the
// v2 encrypt streaming flow but with the v1 key schedule:
//   - keyfile XOR BEFORE HKDF (v1 timing; kdf.go DIFFERENCE 1)
//   - KeyHash = SHA3-512(xorKey) via header.ComputeV1KeyHash (no header MAC)
//   - HKDF subkey order MAC(0-31), Serpent(32-63) (v1; no header subkey read)
//
// It does NOT use the archived legacy v1.49 GUI source in testdata/legacy
// ("DO NOT USE"); it uses in-tree primitives only.
func synthesizeV1DupKeyfileVolume(t *testing.T, plaintext []byte, password string) (pcvPath string, dupKeyfiles []string) {
	t.Helper()

	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs: %v", err)
	}

	tmpDir := t.TempDir()

	// Two identical-content keyfiles => unordered XOR cancels to all-zeros.
	keyfileContent := []byte("v1-dup-keyfile-content-for-DATA-02")
	kf1 := filepath.Join(tmpDir, "keyfile_dup_a.bin")
	kf2 := filepath.Join(tmpDir, "keyfile_dup_b.bin")
	if err := os.WriteFile(kf1, keyfileContent, 0600); err != nil {
		t.Fatalf("write keyfile a: %v", err)
	}
	if err := os.WriteFile(kf2, keyfileContent, 0600); err != nil {
		t.Fatalf("write keyfile b: %v", err)
	}
	dupKeyfiles = []string{kf1, kf2}

	// Random crypto values (real salts/nonce/IV).
	salt, err := crypto.RandomBytes(header.SaltSize)
	if err != nil {
		t.Fatalf("salt: %v", err)
	}
	hkdfSalt, err := crypto.RandomBytes(header.HKDFSaltSize)
	if err != nil {
		t.Fatalf("hkdf salt: %v", err)
	}
	serpentIV, err := crypto.RandomBytes(header.SerpentIVSize)
	if err != nil {
		t.Fatalf("serpent iv: %v", err)
	}
	nonce, err := crypto.RandomBytes(header.NonceSize)
	if err != nil {
		t.Fatalf("nonce: %v", err)
	}

	// Step 1: password key (normal mode). Use the deriveVolumeKey seam so the
	// stored v1 KeyHash matches what production decrypt computes — the package
	// TestMain (fast_kdf_test.go) installs a fast Argon2 stub for the whole test
	// run, and Decrypt derives via that same seam.
	key, err := deriveVolumeKey([]byte(password), salt, false)
	if err != nil {
		t.Fatalf("deriveVolumeKey: %v", err)
	}

	// Step 2: keyfile key (even-count dup, unordered) => all-zeros.
	kfResult, err := keyfile.Process(dupKeyfiles, false, nil)
	if err != nil {
		t.Fatalf("keyfile.Process: %v", err)
	}
	if !keyfile.IsDuplicateKeyfileKey(kfResult.Key) {
		t.Fatalf("synthesizer setup: keyfile key is not all-zeros (IsDuplicateKeyfileKey=false); "+
			"even-count duplicate keyfiles must XOR-cancel, got % x", kfResult.Key)
	}

	// Step 3: v1 XORs keyfile key into main key BEFORE HKDF (= key here).
	xorKey := keyfile.XORWithKey(key, kfResult.Key)

	// Step 4: v1 KeyHash = SHA3-512(xorKey) (password verifier; no header MAC).
	keyHash := header.ComputeV1KeyHash(xorKey)

	// Step 5-6: v1 HKDF + subkey order MAC(0-31), Serpent(32-63).
	hkdfStream := crypto.NewHKDFStream(xorKey, hkdfSalt)
	subreader := crypto.NewSubkeyReader(hkdfStream)
	macSub, err := subreader.MACSubkey()
	if err != nil {
		t.Fatalf("MACSubkey: %v", err)
	}
	serpentKey, err := subreader.SerpentKey()
	if err != nil {
		t.Fatalf("SerpentKey: %v", err)
	}

	// Step 7: MAC + cipher suite (normal mode: keyed BLAKE2b-512, no Serpent).
	mac, err := crypto.NewMAC(macSub, false)
	if err != nil {
		t.Fatalf("NewMAC: %v", err)
	}
	suite, err := crypto.NewCipherSuite(xorKey, nonce, serpentKey, serpentIV, mac, subreader.Reader(), false)
	if err != nil {
		t.Fatalf("NewCipherSuite: %v", err)
	}

	// Step 8: header (Version="v1.49", UseKeyfiles, unordered, RS off).
	h := header.NewVolumeHeader(salt, hkdfSalt, serpentIV, nonce)
	h.Version = "v1.49"
	h.Flags = header.Flags{
		Paranoid:       false,
		UseKeyfiles:    true,
		KeyfileOrdered: false,
		ReedSolomon:    false,
		Padded:         false,
	}

	pcvPath = filepath.Join(tmpDir, "v1_dup_keyfile.pcv")
	fout, err := os.OpenFile(pcvPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatalf("create pcv: %v", err)
	}

	w := header.NewWriter(fout, rsCodecs)
	if _, err := w.WriteHeader(h); err != nil {
		_ = fout.Close()
		t.Fatalf("WriteHeader: %v", err)
	}

	// Step 9: stream-encrypt plaintext (RS off => write ciphertext directly).
	// Small plaintext (< 1 MiB) processed in a single block, mirroring the
	// encrypt loop's Serpent->XChaCha20->MAC ordering via suite.Encrypt.
	srcRemaining := plaintext
	buf := make([]byte, util.MiB)
	for len(srcRemaining) > 0 {
		n := copy(buf, srcRemaining)
		srcRemaining = srcRemaining[n:]
		dst := make([]byte, n)
		suite.Encrypt(dst, buf[:n])
		if _, err := fout.Write(dst); err != nil {
			_ = fout.Close()
			t.Fatalf("write ciphertext: %v", err)
		}
	}
	authTag := suite.Sum()

	if err := fout.Sync(); err != nil {
		_ = fout.Close()
		t.Fatalf("sync: %v", err)
	}
	if err := fout.Close(); err != nil {
		t.Fatalf("close pcv: %v", err)
	}

	// Step 10: patch auth values (KeyHash, KeyfileHash, AuthTag).
	foutRW, err := os.OpenFile(pcvPath, os.O_RDWR, 0600)
	if err != nil {
		t.Fatalf("open pcv for auth patch: %v", err)
	}
	offset := header.AuthValuesOffset(len(h.Comments))
	if err := header.WriteAuthValues(foutRW, offset, keyHash, kfResult.Hash, authTag, rsCodecs); err != nil {
		_ = foutRW.Close()
		t.Fatalf("WriteAuthValues: %v", err)
	}
	if err := foutRW.Sync(); err != nil {
		_ = foutRW.Close()
		t.Fatalf("sync auth: %v", err)
	}
	if err := foutRW.Close(); err != nil {
		t.Fatalf("close auth: %v", err)
	}

	return pcvPath, dupKeyfiles
}

// TestV1DuplicateKeyfileWarnOnly proves DATA-02: a legacy v1 volume authored
// with an even-count duplicate keyfile set must stay decryptable (the v1 branch
// must NOT block like the v2 branch), and the duplicate-keyfile XOR cancellation
// must be surfaced as a warning. The effective key is just the password key
// (the all-zeros keyfile key cancels under XOR), so the volume is perfectly
// decryptable — only the WARNING is the deliverable.
func TestV1DuplicateKeyfileWarnOnly(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs: %v", err)
	}

	const password = "v1-dup-keyfile-pw"
	plaintext := []byte("Legacy v1 volume with even-count duplicate keyfiles (XOR cancels).")

	pcvPath, dupKeyfiles := synthesizeV1DupKeyfileVolume(t, plaintext, password)

	// Non-vacuous: confirm the synthesized volume is genuinely v1 so we exercise
	// the IsLegacyV1 branch (decrypt.go:243), not the v2 block.
	func() {
		fin, err := os.Open(pcvPath)
		if err != nil {
			t.Fatalf("open synthesized pcv: %v", err)
		}
		defer func() { _ = fin.Close() }()
		readResult, err := header.NewReader(fin, rsCodecs).ReadHeader()
		if err != nil {
			t.Fatalf("read synthesized header: %v", err)
		}
		if !readResult.Header.IsLegacyV1() {
			t.Fatalf("synthesized volume is not v1 (Version=%q, IsLegacyV1=false); "+
				"test would exercise the v2 dup-keyfile block instead", readResult.Header.Version)
		}
	}()

	reporter := &dupWarnReporter{}
	outputPath := filepath.Join(filepath.Dir(pcvPath), "v1_dup_out.bin")
	decReq := &DecryptRequest{
		InputFile:    pcvPath,
		OutputFile:   outputPath,
		Password:     password,
		Keyfiles:     dupKeyfiles,
		ForceDecrypt: false,
		Reporter:     reporter,
		RSCodecs:     rsCodecs,
	}

	// (a) Decrypt returns nil (NOT ErrDuplicateKeyfiles) — v1 must not block.
	err = Decrypt(context.Background(), decReq)
	if err != nil {
		if perrors.Is(err, perrors.ErrDuplicateKeyfiles) {
			t.Fatalf("v1 decrypt blocked on duplicate keyfiles (ErrDuplicateKeyfiles); "+
				"DATA-02 requires warn-only, never block: %v", err)
		}
		t.Fatalf("Decrypt v1 dup-keyfile volume: %v", err)
	}

	// (b) decrypted output == original plaintext.
	got, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read decrypted output: %v", err)
	}
	if len(got) != len(plaintext) {
		t.Fatalf("decrypted length = %d; want %d", len(got), len(plaintext))
	}
	for i := range plaintext {
		if got[i] != plaintext[i] {
			t.Fatalf("decrypted byte %d = %#x; want %#x", i, got[i], plaintext[i])
		}
	}

	// (c) the duplicate-keyfile warning was surfaced via SetStatus.
	if !reporter.sawDuplicate {
		t.Fatal("no \"duplicate\" warning surfaced on the v1 decrypt path; " +
			"DATA-02 requires log.Warn + ctx.SetStatus mirroring the encrypt-side detection")
	}
}
