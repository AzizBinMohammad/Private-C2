package envelope

import (
	"bytes"
	"testing"
)

func TestCompressDecompressRoundTrip(t *testing.T) {
	data := []byte("hello, this is some data to compress and decompress")

	compressed, err := Compress(data)
	if err != nil {
		t.Fatalf("Compress: %v", err)
	}

	decompressed, err := Decompress(compressed)
	if err != nil {
		t.Fatalf("Decompress: %v", err)
	}

	if !bytes.Equal(data, decompressed) {
		t.Fatalf("round-trip mismatch: got %q, want %q", decompressed, data)
	}
}

func TestCompressDecompressEmptyInput(t *testing.T) {
	compressed, err := Compress([]byte{})
	if err != nil {
		t.Fatalf("Compress empty: %v", err)
	}

	decompressed, err := Decompress(compressed)
	if err != nil {
		t.Fatalf("Decompress empty: %v", err)
	}

	if len(decompressed) != 0 {
		t.Fatalf("expected empty output, got %d bytes", len(decompressed))
	}
}

func TestCompressDecompressLargeInput(t *testing.T) {
	// Create a large repetitive input to test compression effectiveness
	data := bytes.Repeat([]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ"), 10000)

	compressed, err := Compress(data)
	if err != nil {
		t.Fatalf("Compress large: %v", err)
	}

	// Repetitive data should compress significantly
	if len(compressed) >= len(data) {
		t.Fatalf("compression should reduce size for repetitive data: original=%d, compressed=%d",
			len(data), len(compressed))
	}

	decompressed, err := Decompress(compressed)
	if err != nil {
		t.Fatalf("Decompress large: %v", err)
	}

	if !bytes.Equal(data, decompressed) {
		t.Fatal("large input round-trip mismatch")
	}
}

func TestDecompressInvalidData(t *testing.T) {
	_, err := Decompress([]byte("this is not gzip data"))
	if err == nil {
		t.Fatal("Decompress should fail on invalid gzip data")
	}
}
