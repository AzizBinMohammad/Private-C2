// Package bof parses and relocates COFF object files used as Beacon Object
// Files. Parsing and relocation planning are platform-independent and unit
// tested; execution (Beacon API callbacks and in-memory invocation) is built
// only for Windows and is intended for lab verification.
package bof

import (
	"encoding/binary"
	"fmt"
	"strings"
)

const (
	// MachineAMD64 is IMAGE_FILE_MACHINE_AMD64.
	MachineAMD64 = 0x8664

	coffHeaderSize    = 20
	sectionHeaderSize = 40
	symbolSize        = 18
	relocationSize    = 10
	maxSections       = 96
	maxSymbols        = 1 << 20
	maxRelocations    = 1 << 20
	maxImageSize      = 256 << 20
)

// Relocation is one COFF relocation entry.
type Relocation struct {
	VirtualAddress uint32
	SymbolIndex    uint32
	Type           uint16
}

// Section is one COFF section.
type Section struct {
	Name                string
	VirtualSize         uint32
	VirtualAddress      uint32
	SizeOfRawData       uint32
	PointerToRawData    uint32
	NumberOfRelocations uint16
	Characteristics     uint32
	Raw                 []byte
	Relocations         []Relocation
}

// Symbol is one COFF symbol. Auxiliary records are skipped but Index preserves
// the original table position so relocations resolve correctly.
type Symbol struct {
	Name          string
	Value         uint32
	SectionNumber int16
	Type          uint16
	StorageClass  uint8
	Index         uint32
}

// File is a parsed COFF object.
type File struct {
	Machine  uint16
	Sections []Section
	Symbols  []Symbol
}

func le32(data []byte, off int) uint32 { return binary.LittleEndian.Uint32(data[off:]) }
func le16(data []byte, off int) uint16 { return binary.LittleEndian.Uint16(data[off:]) }

func bounds(data []byte, off, size uint64) ([]byte, error) {
	if off > uint64(len(data)) || size > uint64(len(data))-off {
		return nil, fmt.Errorf("COFF offset %d+%d is outside the %d-byte file", off, size, len(data))
	}
	return data[off : off+size], nil
}

// Parse validates and decodes a COFF object. Only AMD64 objects are accepted.
func Parse(data []byte) (*File, error) {
	if len(data) < coffHeaderSize {
		return nil, fmt.Errorf("COFF file is truncated (%d bytes)", len(data))
	}
	machine := le16(data, 0)
	if machine != MachineAMD64 {
		return nil, fmt.Errorf("unsupported COFF machine 0x%x (only AMD64 is supported)", machine)
	}
	numberOfSections := int(le16(data, 2))
	if numberOfSections < 1 || numberOfSections > maxSections {
		return nil, fmt.Errorf("invalid COFF section count %d", numberOfSections)
	}
	symbolTable := uint64(le32(data, 8))
	numberOfSymbols := uint64(le32(data, 12))
	optionalHeaderSize := uint64(le16(data, 16))
	if numberOfSymbols > maxSymbols {
		return nil, fmt.Errorf("COFF symbol count %d exceeds the limit", numberOfSymbols)
	}
	if numberOfSymbols > 0 {
		if _, err := bounds(data, symbolTable, numberOfSymbols*symbolSize); err != nil {
			return nil, fmt.Errorf("symbol table: %w", err)
		}
	}

	stringsOff := symbolTable + numberOfSymbols*symbolSize
	var stringsTable []byte
	if stringsOff <= uint64(len(data)) {
		if stringsOff == uint64(len(data)) {
			stringsTable = nil
		} else {
			if _, err := bounds(data, stringsOff, 4); err != nil {
				return nil, fmt.Errorf("string table: %w", err)
			}
			stringSize := uint64(le32(data, int(stringsOff)))
			if stringSize < 4 {
				return nil, fmt.Errorf("invalid COFF string table size %d", stringSize)
			}
			if _, err := bounds(data, stringsOff, stringSize); err != nil {
				return nil, fmt.Errorf("string table: %w", err)
			}
			stringsTable = data[stringsOff : stringsOff+stringSize]
		}
	}

	stringAt := func(offset uint32) (string, error) {
		if offset < 4 || uint64(offset) >= uint64(len(stringsTable)) {
			return "", fmt.Errorf("invalid COFF string offset %d", offset)
		}
		rest := stringsTable[offset:]
		end := 0
		for end < len(rest) && rest[end] != 0 {
			end++
		}
		return string(rest[:end]), nil
	}
	nameFromRaw := func(raw []byte) (string, error) {
		if len(raw) >= 8 && raw[0] == 0 && raw[1] == 0 && raw[2] == 0 && raw[3] == 0 {
			return stringAt(le32(raw, 4))
		}
		end := 0
		for end < len(raw) && raw[end] != 0 {
			end++
		}
		return string(raw[:end]), nil
	}

	sectionStart := uint64(coffHeaderSize) + optionalHeaderSize
	file := &File{Machine: machine, Sections: make([]Section, 0, numberOfSections)}
	for i := 0; i < numberOfSections; i++ {
		off := sectionStart + uint64(i*sectionHeaderSize)
		header, err := bounds(data, off, sectionHeaderSize)
		if err != nil {
			return nil, fmt.Errorf("section %d: %w", i, err)
		}
		name := strings.TrimRight(string(header[0:8]), "\x00")
		if strings.HasPrefix(name, "/") {
			var strOff uint32
			if _, err := fmt.Sscanf(name[1:], "%d", &strOff); err == nil {
				if resolved, err := stringAt(strOff); err == nil {
					name = resolved
				}
			}
		}
		section := Section{
			Name:                name,
			VirtualSize:         le32(header, 8),
			VirtualAddress:      le32(header, 12),
			SizeOfRawData:       le32(header, 16),
			PointerToRawData:    le32(header, 20),
			NumberOfRelocations: le16(header, 32),
			Characteristics:     le32(header, 36),
		}
		if section.SizeOfRawData > 0 {
			raw, err := bounds(data, uint64(section.PointerToRawData), uint64(section.SizeOfRawData))
			if err != nil {
				return nil, fmt.Errorf("section %q data: %w", name, err)
			}
			section.Raw = raw
		}
		if section.SizeOfRawData > maxImageSize {
			return nil, fmt.Errorf("section %q is too large", name)
		}

		relocCount := int(section.NumberOfRelocations)
		if relocCount > maxRelocations {
			return nil, fmt.Errorf("section %q has too many relocations", name)
		}
		if relocCount > 0 {
			relocOff := uint64(le32(header, 24)) // PointerToRelocations
			if relocOff == 0 {
				return nil, fmt.Errorf("section %q has relocations but no relocation table", name)
			}
			relocBytes, err := bounds(data, relocOff, uint64(relocCount*relocationSize))
			if err != nil {
				return nil, fmt.Errorf("section %q relocations: %w", name, err)
			}
			section.Relocations = make([]Relocation, relocCount)
			for j := 0; j < relocCount; j++ {
				r := relocBytes[j*relocationSize:]
				section.Relocations[j] = Relocation{
					VirtualAddress: le32(r, 0),
					SymbolIndex:    le32(r, 4),
					Type:           le16(r, 8),
				}
			}
		}
		file.Sections = append(file.Sections, section)
	}

	for i := uint64(0); i < numberOfSymbols; {
		off := symbolTable + i*symbolSize
		raw, err := bounds(data, off, symbolSize)
		if err != nil {
			return nil, fmt.Errorf("symbol %d: %w", i, err)
		}
		name, err := nameFromRaw(raw[0:8])
		if err != nil {
			return nil, err
		}
		symbol := Symbol{
			Name:          name,
			Value:         le32(raw, 8),
			SectionNumber: int16(le16(raw, 12)),
			Type:          le16(raw, 14),
			StorageClass:  raw[16],
			Index:         uint32(i),
		}
		file.Symbols = append(file.Symbols, symbol)
		aux := uint64(raw[17])
		if aux > numberOfSymbols-i {
			return nil, fmt.Errorf("symbol %d has invalid auxiliary count %d", i, aux)
		}
		i += 1 + aux
	}
	return file, nil
}
