package bof

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sync"
	"unsafe"
)

// dataParser mirrors Cobalt Strike's datap layout:
//
//	struct { char *original; char *buffer; int length; int size; }
type dataParser struct {
	Original unsafe.Pointer
	Buffer   unsafe.Pointer
	Length   int32
	Size     int32
}

func dataParse(p *dataParser, buffer unsafe.Pointer, length int32) {
	if p == nil || length < 0 {
		return
	}
	p.Original = buffer
	p.Buffer = buffer
	p.Length = length
	p.Size = length
}

func dataBytes(p *dataParser) []byte {
	if p == nil || p.Buffer == nil || p.Length <= 0 {
		return nil
	}
	return unsafe.Slice((*byte)(p.Buffer), int(p.Length))
}

func dataAdvance(p *dataParser, n int) {
	if p == nil || n <= 0 {
		return
	}
	p.Buffer = unsafe.Add(p.Buffer, n)
	p.Length -= int32(n)
}

// dataExtract reads a big-endian uint32 length followed by that many bytes.
func dataExtract(p *dataParser) (unsafe.Pointer, int32) {
	b := dataBytes(p)
	if len(b) < 4 {
		return nil, 0
	}
	n := int32(binary.BigEndian.Uint32(b[:4]))
	if n < 0 || int(n)+4 > len(b) {
		return nil, 0
	}
	ptr := unsafe.Pointer(&b[4])
	dataAdvance(p, 4+int(n))
	return ptr, n
}

func dataInt(p *dataParser) int32 {
	b := dataBytes(p)
	if len(b) < 4 {
		return 0
	}
	v := int32(binary.BigEndian.Uint32(b[:4]))
	dataAdvance(p, 4)
	return v
}

func dataShort(p *dataParser) int16 {
	b := dataBytes(p)
	if len(b) < 2 {
		return 0
	}
	v := int16(binary.BigEndian.Uint16(b[:2]))
	dataAdvance(p, 2)
	return v
}

func dataRemaining(p *dataParser) int32 {
	if p == nil {
		return 0
	}
	return p.Length
}

// formatBuffer mirrors Cobalt Strike's formatp layout.
type formatBuffer struct {
	Original unsafe.Pointer
	Buffer   unsafe.Pointer
	Length   int32
	Size     int32
}

func formatInit(f *formatBuffer, memory unsafe.Pointer, size int32) {
	if f == nil {
		return
	}
	f.Original = memory
	f.Buffer = memory
	f.Length = 0
	f.Size = size
}

func formatAppend(f *formatBuffer, data unsafe.Pointer, length int32) {
	if f == nil || f.Original == nil || data == nil || length <= 0 {
		return
	}
	if f.Length+length > f.Size {
		return
	}
	dst := unsafe.Slice((*byte)(f.Buffer), int(length))
	src := unsafe.Slice((*byte)(data), int(length))
	copy(dst, src)
	f.Buffer = unsafe.Add(f.Buffer, length)
	f.Length += length
}

func formatToString(f *formatBuffer) (unsafe.Pointer, int32) {
	if f == nil || f.Original == nil {
		return nil, 0
	}
	if f.Length < f.Size {
		terminator := unsafe.Slice((*byte)(f.Buffer), 1)
		terminator[0] = 0
	}
	return f.Original, f.Length
}

func formatReset(f *formatBuffer) {
	if f == nil {
		return
	}
	f.Buffer = f.Original
	f.Length = 0
}

// OutputCollector accumulates BeaconOutput/BeaconError text for one BOF run.
type OutputCollector struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *OutputCollector) append(kind string, data []byte) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if kind == "error" {
		c.buf.WriteString("[bof error] ")
	}
	c.buf.Write(data)
	if len(data) == 0 || data[len(data)-1] != '\n' {
		c.buf.WriteByte('\n')
	}
}

// String returns everything the BOF emitted.
func (c *OutputCollector) String() string {
	if c == nil {
		return ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

func (c *OutputCollector) appendString(kind string, data unsafe.Pointer, length int32) {
	if data == nil || length <= 0 || length > 1<<20 {
		return
	}
	c.append(kind, unsafe.Slice((*byte)(data), int(length)))
}

// Result is what a successful BOF execution returns.
type Result struct {
	Output string `json:"output"`
}

// ErrUnsupported reports execution on a non-Windows build.
var ErrUnsupported = fmt.Errorf("BOF execution requires Windows")
