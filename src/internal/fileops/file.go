package fileops

import (
	"fmt"
	"os"
)

// CreateSecureNoSymlink creates or truncates a file unless the leaf is a symlink.
// It is the only sanctioned write-creation primitive (SEC-02): the plain CreateSecure was retired
// so an unguarded O_CREATE that follows a pre-planted symlink cannot be reintroduced.
func CreateSecureNoSymlink(path string) (*os.File, error) {
	f, err := openFileNoFollow(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err == nil {
		return f, nil
	}

	if info, lerr := os.Lstat(path); lerr == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("refusing to open symlink: %s", path)
		}
		if info.IsDir() {
			return nil, fmt.Errorf("path exists as directory: %s", path)
		}
	}
	return nil, err
}

// OpenExistingNoSymlink opens an existing file for writes without following a
// symlink planted at the leaf path. Callers must pass only non-creating flags.
func OpenExistingNoSymlink(path string, flag int) (*os.File, error) {
	if flag&os.O_CREATE != 0 {
		return nil, fmt.Errorf("OpenExistingNoSymlink called with O_CREATE: %s", path)
	}
	f, err := openFileNoFollow(path, flag, 0)
	if err == nil {
		return f, nil
	}

	if info, lerr := os.Lstat(path); lerr == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("refusing to open symlink: %s", path)
		}
		if info.IsDir() {
			return nil, fmt.Errorf("path exists as directory: %s", path)
		}
	}
	return nil, err
}

// overwriteChunkSize is the working-buffer size for the zero-overwrite pass.
// A fixed chunk (not make([]byte, info.Size())) keeps the helper O(1) in memory
// even for multi-GiB recombined temp files.
const overwriteChunkSize = 64 * 1024

// removeFile is the unlink seam used by OverwriteAndRemove. It is an UNEXPORTED
// package var so the white-box SEC-04 tests (same package, file_test.go) can
// intercept the on-disk bytes at the instant after the overwrite but before the
// unlink, proving overwrite-before-unlink ordering. It is deliberately not
// exported (WR-02): no production binary ships a public hook that an importer
// could swap to disable secure unlinking. Production code always uses os.Remove.
var removeFile = os.Remove

// OverwriteAndRemove best-effort overwrites a file's bytes with zeros, then
// unlinks it. It is used to clean up plaintext / sensitive temp artifacts
// (SEC-04) so a recovered fragment is not left intact on disk after a
// failed/aborted run.
//
// The file is opened O_WRONLY with NO O_CREATE and NO O_TRUNC: O_TRUNC would
// zero the length to 0 before the overwrite could run, defeating the purpose.
// The existing length is overwritten with zeros in fixed 64 KiB chunks (never a
// single info.Size() allocation), Sync()'d, Closed, and then removed.
//
// Best-effort: the os.Remove is ALWAYS attempted, even when the open/overwrite
// fails — the artifact is never left behind. The returned error is the remove
// error (for testability); callers keep the `_ = OverwriteAndRemove(...)`
// non-fatal-cleanup ergonomics, except the error-checked deniability .tmp site.
//
// SECURITY NOTE: This is best-effort only. On SSDs (wear-leveling /
// copy-on-write) and on journaling/CoW filesystems, the original bytes may
// persist in unreachable physical blocks that an application-layer overwrite
// cannot reach. Like crypto.SecureZero, this significantly reduces the recovery
// window but cannot guarantee complete erasure.
func OverwriteAndRemove(path string) error {
	// #nosec G304 -- path is an internal temp file, validated by caller.
	// The no-follow open is load-bearing: cleanup must never overwrite a
	// symlink target planted at a .incomplete/.tmp path.
	if f, err := openFileNoFollow(path, os.O_WRONLY, 0); err == nil {
		if info, statErr := f.Stat(); statErr == nil {
			zeros := make([]byte, overwriteChunkSize)
			remaining := info.Size()
			for remaining > 0 {
				n := int64(len(zeros))
				if n > remaining {
					n = remaining
				}
				if _, werr := f.Write(zeros[:n]); werr != nil {
					break
				}
				remaining -= n
			}
			_ = f.Sync()
		}
		_ = f.Close()
	}
	// Always attempt removal — never leave the artifact behind, even on a prior error.
	return removeFile(path)
}
