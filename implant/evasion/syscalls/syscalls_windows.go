//go:build windows

package syscalls

import (
	"fmt"
	"sync"
	"unsafe"
)

// windowsSyscaller implements direct NT syscall invocation on Windows,
// bypassing ntdll.dll user-mode hooks.
//
// TODO: Implement the following for production use:
//   - Resolve syscall numbers dynamically from ntdll.dll on disk
//   - Use Hell's Gate / Halo's Gate technique for runtime syscall number resolution
//   - Support for indirect syscalls (jumping into ntdll syscall;ret gadgets)
//   - Add support for Wow64 (32-bit on 64-bit) transitions
type windowsSyscaller struct {
	mu             sync.RWMutex
	syscallNumbers map[string]uint16
	initialized    bool
}

// Well-known NT syscall names (numbers vary by Windows version).
const (
	NtAllocateVirtualMemory = "NtAllocateVirtualMemory"
	NtProtectVirtualMemory  = "NtProtectVirtualMemory"
	NtWriteVirtualMemory    = "NtWriteVirtualMemory"
	NtCreateThreadEx        = "NtCreateThreadEx"
	NtOpenProcess           = "NtOpenProcess"
	NtClose                 = "NtClose"
	NtQuerySystemInformation = "NtQuerySystemInformation"
	NtQueryInformationProcess = "NtQueryInformationProcess"
)

func newPlatformSyscaller() Syscaller {
	return &windowsSyscaller{
		syscallNumbers: make(map[string]uint16),
	}
}

// Execute invokes an NT syscall by number.
// TODO: Replace with actual assembly stub that executes:
//
//	mov r10, rcx
//	mov eax, <syscall_number>
//	syscall
//	ret
func (w *windowsSyscaller) Execute(number uintptr, args ...uintptr) (uintptr, error) {
	// TODO: This is a placeholder. In production, this would:
	// 1. Set up the correct register state
	// 2. Execute the syscall instruction directly
	// 3. Return the NTSTATUS value
	_ = unsafe.Pointer(nil) // reference unsafe to keep the import for future use
	return 0, fmt.Errorf("NT syscall stub not yet implemented (syscall number: %d)", number)
}

func (w *windowsSyscaller) Name() string {
	return "windows-nt"
}

func (w *windowsSyscaller) Available() bool {
	// TODO: Return true once the assembly stubs are implemented.
	return false
}

// ResolveSyscallNumber looks up the syscall number for a given NT function name.
// TODO: Implement by reading ntdll.dll from disk and parsing the export table
// to extract the syscall number from the function stub (mov eax, <number>).
func (w *windowsSyscaller) ResolveSyscallNumber(functionName string) (uint16, error) {
	w.mu.RLock()
	if num, ok := w.syscallNumbers[functionName]; ok {
		w.mu.RUnlock()
		return num, nil
	}
	w.mu.RUnlock()

	// TODO: Read ntdll.dll from disk, parse PE headers, find the export,
	// read the syscall number from the stub bytes.
	return 0, fmt.Errorf("syscall number resolution not yet implemented for %s", functionName)
}

// CacheSyscallNumber stores a resolved syscall number for later use.
func (w *windowsSyscaller) CacheSyscallNumber(functionName string, number uint16) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.syscallNumbers[functionName] = number
}
