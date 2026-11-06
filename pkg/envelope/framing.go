package envelope

import (
	"encoding/binary"
	"errors"
	"io"
)

const (
	// MaxMessageSize bounds a single frame before allocation. Large transfers
	// must be chunked; a length prefix is not a licence to allocate gigabytes.
	MaxMessageSize  = 64 << 20 // 64 MiB
	LengthFieldSize = 4
)

var (
	ErrMessageTooLarge = errors.New("message exceeds maximum size")
	ErrTruncated       = errors.New("truncated message")
)

func WriteFrame(w io.Writer, data []byte) error {
	if len(data) > MaxMessageSize {
		return ErrMessageTooLarge
	}

	length := make([]byte, LengthFieldSize)
	binary.LittleEndian.PutUint32(length, uint32(len(data)))

	if _, err := w.Write(length); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

// ReadFrame reads a frame using the default maximum size.
func ReadFrame(r io.Reader) ([]byte, error) {
	return ReadFrameWithLimit(r, MaxMessageSize)
}

// ReadFrameWithLimit reads a frame and rejects an oversized length prefix
// before allocating the payload buffer. A limit of zero uses MaxMessageSize.
func ReadFrameWithLimit(r io.Reader, limit uint32) ([]byte, error) {
	if limit == 0 {
		limit = MaxMessageSize
	}

	lengthBuf := make([]byte, LengthFieldSize)
	if _, err := io.ReadFull(r, lengthBuf); err != nil {
		return nil, err
	}

	length := binary.LittleEndian.Uint32(lengthBuf)
	if length > limit {
		return nil, ErrMessageTooLarge
	}

	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, ErrTruncated
	}

	return data, nil
}
