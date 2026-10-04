package envelope

import (
	"encoding/binary"
	"errors"
	"io"
)

const (
	MaxMessageSize = 2 << 30 // 2 GB
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

func ReadFrame(r io.Reader) ([]byte, error) {
	lengthBuf := make([]byte, LengthFieldSize)
	if _, err := io.ReadFull(r, lengthBuf); err != nil {
		return nil, err
	}

	length := binary.LittleEndian.Uint32(lengthBuf)
	if length > MaxMessageSize {
		return nil, ErrMessageTooLarge
	}

	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, ErrTruncated
	}

	return data, nil
}
