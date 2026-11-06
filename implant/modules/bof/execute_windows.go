//go:build windows

package bof

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Execute maps a COFF object into executable memory, applies relocations
// against the Beacon API callback table, and calls its "go" entry point with
// args. The BOF runs on the calling goroutine's thread.
func Execute(coffBytes, args []byte) (Result, error) {
	file, err := Parse(coffBytes)
	if err != nil {
		return Result{}, err
	}
	layout, err := Plan(file, 0)
	if err != nil {
		return Result{}, err
	}
	if layout.ImageSize == 0 {
		return Result{}, fmt.Errorf("COFF image is empty")
	}

	mem, err := windows.VirtualAlloc(0, layout.ImageSize,
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	if err != nil {
		return Result{}, fmt.Errorf("allocating BOF image: %w", err)
	}
	defer func() {
		_ = windows.VirtualFree(mem, 0, windows.MEM_RELEASE)
	}()

	layout, err = Plan(file, mem)
	if err != nil {
		return Result{}, err
	}
	image := unsafe.Slice((*byte)(unsafe.Pointer(mem)), int(layout.ImageSize))

	collector := &OutputCollector{}
	imports := buildImports(collector)
	resolve := func(name string) (uintptr, bool) {
		addr, ok := imports[name]
		return addr, ok
	}
	if err := Apply(file, layout, image, resolve); err != nil {
		return Result{}, err
	}

	entry, err := entryPoint(file, layout, resolve)
	if err != nil {
		return Result{}, err
	}

	var argsPtr uintptr
	if len(args) > 0 {
		argsPtr = uintptr(unsafe.Pointer(&args[0]))
	}
	syscall.SyscallN(entry, argsPtr, uintptr(len(args)))
	return Result{Output: collector.String()}, nil
}

func entryPoint(file *File, layout *Layout, resolve func(string) (uintptr, bool)) (uintptr, error) {
	for _, symbol := range file.Symbols {
		if symbol.Name != "go" {
			continue
		}
		if symbol.SectionNumber <= 0 {
			break
		}
		return symbolAddress(file, layout, symbol, resolve)
	}
	return 0, fmt.Errorf("COFF object has no defined \"go\" entry point")
}
