package dns

import (
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
)

// Encoding uses base32 (hex variant, no padding) for DNS-safe subdomain encoding.
var dnsEncoding = base32.HexEncoding.WithPadding(base32.NoPadding)

// chunkHeader is prepended to each chunk for reassembly.
// Format: [2 bytes seqID][2 bytes totalChunks][data...]
const chunkHeaderSize = 4

// EncodeChunk encodes a data chunk with sequence metadata for DNS transmission.
// Returns a lowercase base32 string safe for use in DNS labels.
func EncodeChunk(data []byte, seqID, totalChunks uint16) string {
	header := make([]byte, chunkHeaderSize)
	binary.BigEndian.PutUint16(header[0:2], seqID)
	binary.BigEndian.PutUint16(header[2:4], totalChunks)

	payload := append(header, data...)
	return strings.ToLower(dnsEncoding.EncodeToString(payload))
}

// DecodeChunk decodes a base32-encoded DNS chunk, returning the sequence ID,
// total chunk count, and the data payload.
func DecodeChunk(encoded string) (seqID, totalChunks uint16, data []byte, err error) {
	decoded, err := dnsEncoding.DecodeString(strings.ToUpper(encoded))
	if err != nil {
		return 0, 0, nil, fmt.Errorf("base32 decode: %w", err)
	}
	if len(decoded) < chunkHeaderSize {
		return 0, 0, nil, fmt.Errorf("chunk too small: %d bytes", len(decoded))
	}

	seqID = binary.BigEndian.Uint16(decoded[0:2])
	totalChunks = binary.BigEndian.Uint16(decoded[2:4])
	data = decoded[chunkHeaderSize:]
	return seqID, totalChunks, data, nil
}

// DecodeChunkData is a convenience function that decodes and returns only
// the data portion of a chunk (stripping the header).
func DecodeChunkData(encoded string) []byte {
	_, _, data, err := DecodeChunk(encoded)
	if err != nil {
		return nil
	}
	return data
}

// ChunkData splits data into chunks of at most maxSize bytes each.
func ChunkData(data []byte, maxSize int) [][]byte {
	if maxSize <= 0 {
		maxSize = 90
	}

	var chunks [][]byte
	for len(data) > 0 {
		end := maxSize
		if end > len(data) {
			end = len(data)
		}
		chunk := make([]byte, end)
		copy(chunk, data[:end])
		chunks = append(chunks, chunk)
		data = data[end:]
	}
	if len(chunks) == 0 {
		chunks = append(chunks, []byte{})
	}
	return chunks
}

// ReassembleChunks reassembles a set of ordered chunks into the original data.
// The chunks map is keyed by sequence ID.
type ReassemblyBuffer struct {
	chunks     map[uint16][]byte
	total      uint16
	receivedAt map[uint16]bool
}

// NewReassemblyBuffer creates a new reassembly buffer expecting totalChunks.
func NewReassemblyBuffer(totalChunks uint16) *ReassemblyBuffer {
	return &ReassemblyBuffer{
		chunks:     make(map[uint16][]byte),
		total:      totalChunks,
		receivedAt: make(map[uint16]bool),
	}
}

// AddChunk adds a chunk to the buffer. Returns true if all chunks have been received.
func (r *ReassemblyBuffer) AddChunk(seqID uint16, data []byte) bool {
	r.chunks[seqID] = data
	r.receivedAt[seqID] = true
	return uint16(len(r.chunks)) >= r.total
}

// Assemble returns the fully reassembled data, or an error if chunks are missing.
func (r *ReassemblyBuffer) Assemble() ([]byte, error) {
	if uint16(len(r.chunks)) < r.total {
		return nil, fmt.Errorf("incomplete: have %d of %d chunks", len(r.chunks), r.total)
	}

	var result []byte
	for i := uint16(0); i < r.total; i++ {
		chunk, ok := r.chunks[i]
		if !ok {
			return nil, fmt.Errorf("missing chunk %d", i)
		}
		result = append(result, chunk...)
	}
	return result, nil
}

// IsComplete returns whether all chunks have been received.
func (r *ReassemblyBuffer) IsComplete() bool {
	return uint16(len(r.chunks)) >= r.total
}

// EncodeDNSSafe encodes arbitrary bytes into a DNS-label-safe string
// using base32 hex encoding without padding.
func EncodeDNSSafe(data []byte) string {
	return strings.ToLower(dnsEncoding.EncodeToString(data))
}

// DecodeDNSSafe decodes a DNS-label-safe base32 string back to bytes.
func DecodeDNSSafe(encoded string) ([]byte, error) {
	return dnsEncoding.DecodeString(strings.ToUpper(encoded))
}
