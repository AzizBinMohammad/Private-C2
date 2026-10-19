package envelope

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestWriteReadFrameRoundTrip(t *testing.T) {
	data := []byte("hello, framed world")

	var buf bytes.Buffer
	if err := WriteFrame(&buf, data); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	got, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}

	if !bytes.Equal(data, got) {
		t.Fatalf("round-trip mismatch: got %q, want %q", got, data)
	}
}

func TestFrameEmptyMessage(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, []byte{}); err != nil {
		t.Fatalf("WriteFrame empty: %v", err)
	}

	got, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame empty: %v", err)
	}

	if len(got) != 0 {
		t.Fatalf("expected empty data, got %d bytes", len(got))
	}
}

func TestFrameMultipleMessages(t *testing.T) {
	messages := [][]byte{
		[]byte("first"),
		[]byte("second"),
		[]byte("third"),
	}

	var buf bytes.Buffer
	for _, msg := range messages {
		if err := WriteFrame(&buf, msg); err != nil {
			t.Fatalf("WriteFrame: %v", err)
		}
	}

	for i, want := range messages {
		got, err := ReadFrame(&buf)
		if err != nil {
			t.Fatalf("ReadFrame %d: %v", i, err)
		}
		if !bytes.Equal(want, got) {
			t.Fatalf("message %d mismatch: got %q, want %q", i, got, want)
		}
	}
}

func TestWriteFrameMaxSizeEnforcement(t *testing.T) {
	if MaxMessageSize != 64<<20 {
		t.Fatalf("unexpected MaxMessageSize: %d", MaxMessageSize)
	}
}

func TestReadFrameRejectsOversizedLengthBeforeAllocation(t *testing.T) {
	// A hostile peer can claim a huge frame with four bytes. The reader must
	// reject it before allocating the payload buffer.
	header := make([]byte, LengthFieldSize)
	binary.LittleEndian.PutUint32(header, MaxMessageSize+1)

	_, err := ReadFrame(bytes.NewReader(header))
	if err != ErrMessageTooLarge {
		t.Fatalf("expected ErrMessageTooLarge, got %v", err)
	}
}

func TestReadFrameWithLimit(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, make([]byte, 100)); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	_, err := ReadFrameWithLimit(bytes.NewReader(buf.Bytes()), 50)
	if err != ErrMessageTooLarge {
		t.Fatalf("expected ErrMessageTooLarge, got %v", err)
	}
}

func TestReadFrameTruncated(t *testing.T) {
	// Write a valid frame header claiming 100 bytes, but only provide 10 bytes of data
	var buf bytes.Buffer
	if err := WriteFrame(&buf, make([]byte, 100)); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	// Truncate the buffer to only include header + 10 bytes
	data := buf.Bytes()[:LengthFieldSize+10]
	reader := bytes.NewReader(data)

	_, err := ReadFrame(reader)
	if err != ErrTruncated {
		t.Fatalf("expected ErrTruncated, got %v", err)
	}
}
