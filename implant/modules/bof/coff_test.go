package bof

import (
	"encoding/binary"
	"testing"
	"unsafe"
)

// buildObject creates a one-section AMD64 COFF object:
//
//	.text: 8 bytes of raw data
//	one relocation at offset 0 against the external symbol "BeaconOutput"
func buildObject(relocType uint16) []byte {
	const (
		headerSize = 20
		sectionAt  = headerSize
		rawAt      = sectionAt + 40
		rawSize    = 8
		symbolAt   = rawAt + rawSize
		symbolSize = 18
		stringsAt  = symbolAt + symbolSize
	)
	name := "BeaconOutput\x00" // 13 bytes
	stringTableSize := 4 + len(name)
	relocAt := stringsAt + stringTableSize

	data := make([]byte, relocAt+10)
	binary.LittleEndian.PutUint16(data[0:], MachineAMD64)
	binary.LittleEndian.PutUint16(data[2:], 1) // sections
	binary.LittleEndian.PutUint32(data[8:], symbolAt)
	binary.LittleEndian.PutUint32(data[12:], 1) // symbols
	binary.LittleEndian.PutUint16(data[16:], 0) // optional header

	// Section header.
	copy(data[sectionAt:sectionAt+8], ".text\x00\x00\x00")
	binary.LittleEndian.PutUint32(data[sectionAt+8:], rawSize)
	binary.LittleEndian.PutUint32(data[sectionAt+16:], rawSize)
	binary.LittleEndian.PutUint32(data[sectionAt+20:], rawAt)
	binary.LittleEndian.PutUint32(data[sectionAt+24:], uint32(relocAt))
	binary.LittleEndian.PutUint16(data[sectionAt+32:], 1) // relocations

	// Symbol: zeroes + string-table offset 4.
	binary.LittleEndian.PutUint32(data[symbolAt+4:], 4)
	binary.LittleEndian.PutUint16(data[symbolAt+12:], 0) // undefined
	data[symbolAt+16] = 2                                // external

	// String table.
	binary.LittleEndian.PutUint32(data[stringsAt:], uint32(stringTableSize))
	copy(data[stringsAt+4:], name)

	// Relocation.
	binary.LittleEndian.PutUint32(data[relocAt:], 0)
	binary.LittleEndian.PutUint32(data[relocAt+4:], 0)
	binary.LittleEndian.PutUint16(data[relocAt+8:], relocType)
	return data
}

func TestParse(t *testing.T) {
	file, err := Parse(buildObject(relAddr64))
	if err != nil {
		t.Fatal(err)
	}
	if file.Machine != MachineAMD64 || len(file.Sections) != 1 {
		t.Fatalf("unexpected file: %+v", file)
	}
	if file.Sections[0].Name != ".text" || len(file.Sections[0].Raw) != 8 {
		t.Fatalf("unexpected section: %+v", file.Sections[0])
	}
	if len(file.Sections[0].Relocations) != 1 || file.Sections[0].Relocations[0].SymbolIndex != 0 {
		t.Fatalf("unexpected relocations: %+v", file.Sections[0].Relocations)
	}
	if len(file.Symbols) != 1 || file.Symbols[0].Name != "BeaconOutput" || file.Symbols[0].SectionNumber != 0 {
		t.Fatalf("unexpected symbols: %+v", file.Symbols)
	}
}

func TestApplyAddr64(t *testing.T) {
	file, err := Parse(buildObject(relAddr64))
	if err != nil {
		t.Fatal(err)
	}
	const base = uintptr(0x10000000)
	layout, err := Plan(file, base)
	if err != nil {
		t.Fatal(err)
	}
	image := make([]byte, layout.ImageSize)
	const target = uintptr(0x20000000)
	if err := Apply(file, layout, image, func(name string) (uintptr, bool) {
		if name == "BeaconOutput" {
			return target, true
		}
		return 0, false
	}); err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint64(image); got != uint64(target) {
		t.Fatalf("ADDR64 = 0x%x, want 0x%x", got, target)
	}
}

func TestApplyRel32(t *testing.T) {
	file, err := Parse(buildObject(relRel32))
	if err != nil {
		t.Fatal(err)
	}
	const base = uintptr(0x10000000)
	layout, err := Plan(file, base)
	if err != nil {
		t.Fatal(err)
	}
	image := make([]byte, layout.ImageSize)
	const target = uintptr(0x20000000)
	if err := Apply(file, layout, image, func(string) (uintptr, bool) { return target, true }); err != nil {
		t.Fatal(err)
	}
	got := int32(binary.LittleEndian.Uint32(image))
	want := int32(int64(target) - int64(base+4))
	if got != want {
		t.Fatalf("REL32 = %d (0x%x), want %d (0x%x)", got, uint32(got), want, uint32(want))
	}
}

func TestApplyUnresolvedSymbol(t *testing.T) {
	file, err := Parse(buildObject(relAddr64))
	if err != nil {
		t.Fatal(err)
	}
	layout, err := Plan(file, 0x1000)
	if err != nil {
		t.Fatal(err)
	}
	image := make([]byte, layout.ImageSize)
	if err := Apply(file, layout, image, func(string) (uintptr, bool) { return 0, false }); err == nil {
		t.Fatal("expected an unresolved symbol error")
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	valid := buildObject(relAddr64)
	cases := map[string][]byte{
		"short":             valid[:10],
		"wrong machine":     append([]byte(nil), valid...),
		"section overflow":  append([]byte(nil), valid...),
		"symbol overflow":   append([]byte(nil), valid...),
		"relocation absent": append([]byte(nil), valid...),
	}
	binary.LittleEndian.PutUint16(cases["wrong machine"], 0x14c)
	binary.LittleEndian.PutUint32(cases["section overflow"][20+20:], 1<<20)
	binary.LittleEndian.PutUint32(cases["symbol overflow"][8:], 1<<30)
	binary.LittleEndian.PutUint32(cases["relocation absent"][20+24:], 0)
	for name, data := range cases {
		if _, err := Parse(data); err == nil {
			t.Errorf("%s unexpectedly parsed", name)
		}
	}
}

func TestDataParser(t *testing.T) {
	buf := make([]byte, 0, 32)
	appendInt := func(v uint32) {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], v)
		buf = append(buf, b[:]...)
	}
	appendShort := func(v uint16) {
		var b [2]byte
		binary.BigEndian.PutUint16(b[:], v)
		buf = append(buf, b[:]...)
	}
	appendInt(3)
	buf = append(buf, 'a', 'b', 'c')
	appendInt(42)
	appendShort(7)

	var p dataParser
	dataParse(&p, unsafe.Pointer(&buf[0]), int32(len(buf)))

	ptr, n := dataExtract(&p)
	if n != 3 || string(unsafe.Slice((*byte)(ptr), 3)) != "abc" {
		t.Fatalf("extract = %d %q", n, string(unsafe.Slice((*byte)(ptr), 3)))
	}
	if got := dataInt(&p); got != 42 {
		t.Fatalf("int = %d", got)
	}
	if got := dataShort(&p); got != 7 {
		t.Fatalf("short = %d", got)
	}
	if got := dataRemaining(&p); got != 0 {
		t.Fatalf("remaining = %d", got)
	}
}

func TestFormatBuffer(t *testing.T) {
	mem := make([]byte, 16)
	var f formatBuffer
	formatInit(&f, unsafe.Pointer(&mem[0]), int32(len(mem)))
	first := []byte("hello ")
	second := []byte("world")
	formatAppend(&f, unsafe.Pointer(&first[0]), int32(len(first)))
	formatAppend(&f, unsafe.Pointer(&second[0]), int32(len(second)))
	ptr, n := formatToString(&f)
	if n != 11 || string(unsafe.Slice((*byte)(ptr), 11)) != "hello world" {
		t.Fatalf("format = %d %q", n, string(unsafe.Slice((*byte)(ptr), 11)))
	}
	formatReset(&f)
	if _, n := formatToString(&f); n != 0 {
		t.Fatalf("reset length = %d", n)
	}
}
