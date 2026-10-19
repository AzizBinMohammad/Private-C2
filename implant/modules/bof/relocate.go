package bof

import (
	"encoding/binary"
	"fmt"
)

// AMD64 relocation types.
const (
	relAbsolute = 0x0000
	relAddr64   = 0x0001
	relAddr32   = 0x0002
	relAddr32NB = 0x0003
	relRel32    = 0x0004
	relRel32Max = 0x0009 // REL32_1 .. REL32_5
)

// Layout places every section in one image. SectionAddr is indexed by the
// zero-based section order; UseAddr resolves COFF's one-based section numbers.
type Layout struct {
	Base        uintptr
	Offsets     []uintptr
	SectionAddr []uintptr
	ImageSize   uintptr
}

// Plan assigns 16-byte-aligned offsets to sections that carry raw data.
func Plan(file *File, base uintptr) (*Layout, error) {
	if file == nil || len(file.Sections) == 0 {
		return nil, fmt.Errorf("COFF file has no sections")
	}
	layout := &Layout{
		Base:        base,
		Offsets:     make([]uintptr, len(file.Sections)),
		SectionAddr: make([]uintptr, len(file.Sections)),
	}
	var offset uintptr
	for i := range file.Sections {
		offset = (offset + 15) &^ 15
		layout.Offsets[i] = offset
		layout.SectionAddr[i] = base + offset
		offset += uintptr(len(file.Sections[i].Raw))
		if offset > maxImageSize {
			return nil, fmt.Errorf("COFF image exceeds the %d-byte limit", maxImageSize)
		}
	}
	layout.ImageSize = offset
	return layout, nil
}

// Apply copies section data into image, resolves symbols, and applies
// relocations. base must match the address at which image is mapped; resolve
// supplies addresses for undefined symbols such as BeaconOutput.
func Apply(file *File, layout *Layout, image []byte, resolve func(name string) (uintptr, bool)) error {
	if file == nil || layout == nil || resolve == nil {
		return fmt.Errorf("Apply requires a parsed file, layout, and resolver")
	}
	if uintptr(len(image)) < layout.ImageSize {
		return fmt.Errorf("image is %d bytes, need %d", len(image), layout.ImageSize)
	}
	if len(layout.Offsets) != len(file.Sections) {
		return fmt.Errorf("layout does not match the COFF file")
	}

	for i := range file.Sections {
		copy(image[layout.Offsets[i]:], file.Sections[i].Raw)
	}

	byIndex := make(map[uint32]Symbol, len(file.Symbols))
	for _, s := range file.Symbols {
		byIndex[s.Index] = s
	}

	for i := range file.Sections {
		for _, rel := range file.Sections[i].Relocations {
			symbol, ok := byIndex[rel.SymbolIndex]
			if !ok {
				return fmt.Errorf("relocation references unknown symbol index %d", rel.SymbolIndex)
			}
			target, err := symbolAddress(file, layout, symbol, resolve)
			if err != nil {
				return err
			}
			place := layout.Offsets[i] + uintptr(rel.VirtualAddress)
			if err := applyRelocation(rel.Type, image, place, layout.Base, target); err != nil {
				return fmt.Errorf("section %q: %w", file.Sections[i].Name, err)
			}
		}
	}
	return nil
}

func symbolAddress(file *File, layout *Layout, symbol Symbol, resolve func(string) (uintptr, bool)) (uintptr, error) {
	switch {
	case symbol.SectionNumber > 0:
		idx := int(symbol.SectionNumber) - 1
		if idx < 0 || idx >= len(layout.SectionAddr) {
			return 0, fmt.Errorf("symbol %q references section %d", symbol.Name, symbol.SectionNumber)
		}
		return layout.SectionAddr[idx] + uintptr(symbol.Value), nil
	case symbol.SectionNumber == 0:
		addr, ok := resolve(symbol.Name)
		if !ok {
			return 0, fmt.Errorf("unresolved COFF symbol %q", symbol.Name)
		}
		return addr, nil
	case symbol.SectionNumber == -1:
		return uintptr(symbol.Value), nil
	default:
		return 0, fmt.Errorf("symbol %q has unsupported section number %d", symbol.Name, symbol.SectionNumber)
	}
}

func applyRelocation(relType uint16, image []byte, place, base, target uintptr) error {
	switch relType {
	case relAbsolute:
		return nil
	case relAddr64:
		if err := checkRange(image, place, 8); err != nil {
			return err
		}
		binary.LittleEndian.PutUint64(image[place:], uint64(target))
	case relAddr32:
		if err := checkRange(image, place, 4); err != nil {
			return err
		}
		binary.LittleEndian.PutUint32(image[place:], uint32(target))
	case relAddr32NB:
		if err := checkRange(image, place, 4); err != nil {
			return err
		}
		binary.LittleEndian.PutUint32(image[place:], uint32(target-base))
	case relRel32, relRel32 + 1, relRel32 + 2, relRel32 + 3, relRel32 + 4, relRel32 + 5:
		if err := checkRange(image, place, 4); err != nil {
			return err
		}
		addend := int32(binary.LittleEndian.Uint32(image[place:]))
		extra := int64(relType - relRel32)
		delta := int64(target) - int64(base+place+4) + int64(addend) + extra
		binary.LittleEndian.PutUint32(image[place:], uint32(int32(delta)))
	default:
		return fmt.Errorf("unsupported AMD64 relocation type 0x%x", relType)
	}
	return nil
}

func checkRange(image []byte, place, size uintptr) error {
	if place > uintptr(len(image)) || size > uintptr(len(image))-place {
		return fmt.Errorf("relocation at offset %d+%d is outside the image", place, size)
	}
	return nil
}
