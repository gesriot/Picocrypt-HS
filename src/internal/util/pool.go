package util

import (
	"sync"
)

// BufferPool provides reusable byte buffers to reduce GC pressure
// during large file operations. Buffers are zeroed before returning
// to pool because they may hold plaintext during encrypt/decrypt.
type BufferPool struct {
	pool sync.Pool
	size int
}

// NewBufferPool creates a new buffer pool with the specified buffer size.
func NewBufferPool(size int) *BufferPool {
	return &BufferPool{
		size: size,
		pool: sync.Pool{
			New: func() any {
				b := make([]byte, size)
				return &b
			},
		},
	}
}

// Get retrieves a buffer from the pool.
// The buffer is zeroed but callers should overwrite entirely.
func (p *BufferPool) Get() []byte {
	return *p.pool.Get().(*[]byte)
}

// zeroPage is a static zero buffer used for zeroing via copy().
// copy() has observable side effects the compiler must preserve.
var zeroPage [4096]byte

// Put returns a buffer to the pool after zeroing it.
// The buffer should not be used after calling Put.
func (p *BufferPool) Put(b []byte) {
	if len(b) != p.size {
		// Don't return mismatched buffers to avoid corruption
		return
	}
	// Zero before returning - buffers may contain plaintext.
	// Uses copy() which has observable effects compiler must preserve.
	for i := 0; i < len(b); i += len(zeroPage) {
		copy(b[i:], zeroPage[:])
	}
	p.pool.Put(&b)
}

// Default buffer pools for common sizes
var (
	// MiBPool provides 1 MiB buffers for encryption/decryption
	MiBPool = NewBufferPool(MiB)

	// SmallPool provides 4 KiB buffers for smaller operations
	SmallPool = NewBufferPool(4 * 1024)
)

// GetMiBBuffer gets a 1 MiB buffer from the default pool.
func GetMiBBuffer() []byte {
	return MiBPool.Get()
}

// PutMiBBuffer returns a 1 MiB buffer to the default pool.
func PutMiBBuffer(b []byte) {
	MiBPool.Put(b)
}

// GetSmallBuffer gets a 4 KiB buffer from the default pool.
func GetSmallBuffer() []byte {
	return SmallPool.Get()
}

// PutSmallBuffer returns a 4 KiB buffer to the default pool.
func PutSmallBuffer(b []byte) {
	SmallPool.Put(b)
}
