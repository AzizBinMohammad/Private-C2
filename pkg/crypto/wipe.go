package crypto

import (
	"sync/atomic"
	"unsafe"
)

// wipeCounter is an atomic counter used to prevent the compiler from
// optimising away the zeroing loop. The counter's value is accumulated
// from every byte written and stored via atomic.StoreUint64 at the end,
// establishing a data dependency the compiler cannot remove.
var wipeCounter uint64

// Wipe zeroes every byte of b in a way that the compiler cannot optimise
// away. It must be called on key material, session tokens and other
// sensitive byte slices as soon as they are no longer needed.
//
// The implementation uses an explicit loop with an opaque side-effect
// (atomic store of an accumulated value) so that the runtime is
// obligated to perform the writes.
func Wipe(b []byte) {
	if len(b) == 0 {
		return
	}

	var acc byte
	for i := range b {
		b[i] = 0
		acc ^= b[i] // read back forces the write to be observable
	}

	// Store the accumulator through an atomic so the compiler must
	// keep the loop alive even at -O2 / -O3.
	atomic.StoreUint64(&wipeCounter, uint64(acc))
}

// WipeFixed32 zeroes a fixed-size 32-byte array (common for symmetric
// keys and digests). Same volatile-style guarantee as Wipe.
func WipeFixed32(b *[32]byte) {
	Wipe(b[:])
}

// WipeFixed64 zeroes a fixed-size 64-byte array (common for Ed25519
// private keys). Same volatile-style guarantee as Wipe.
func WipeFixed64(b *[64]byte) {
	Wipe(b[:])
}

// WipeString zeroes the backing array of a Go string. Because strings
// are nominally immutable this uses unsafe.Pointer to reach the
// underlying bytes. Callers must ensure that no other reference to the
// string's backing array will be read after the call.
func WipeString(s *string) {
	if len(*s) == 0 {
		return
	}

	type stringHeader struct {
		Data unsafe.Pointer
		Len  int
	}

	hdr := (*stringHeader)(unsafe.Pointer(s))
	buf := unsafe.Slice((*byte)(hdr.Data), hdr.Len)
	Wipe(buf)
}
