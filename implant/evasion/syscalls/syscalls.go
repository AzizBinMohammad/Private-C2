package syscalls

import (
	"fmt"
	"runtime"
)

// Syscaller provides an interface for direct syscall invocation,
// bypassing user-mode API hooks. Each platform implements this
// interface with native syscall stubs.
type Syscaller interface {
	// Execute invokes a syscall by number with the given arguments.
	// Returns the result and any error.
	Execute(number uintptr, args ...uintptr) (uintptr, error)

	// Name returns the platform identifier for this syscaller.
	Name() string

	// Available reports whether direct syscall invocation is
	// supported on the current platform.
	Available() bool
}

// SyscallResult holds the return value of a syscall invocation.
type SyscallResult struct {
	Value uintptr
	Err   error
}

// New creates a new platform-appropriate Syscaller.
func New() Syscaller {
	return newPlatformSyscaller()
}

// defaultSyscaller is the fallback for platforms without direct syscall support.
type defaultSyscaller struct{}

func (d *defaultSyscaller) Execute(_ uintptr, _ ...uintptr) (uintptr, error) {
	return 0, fmt.Errorf("direct syscalls not supported on %s/%s", runtime.GOOS, runtime.GOARCH)
}

func (d *defaultSyscaller) Name() string {
	return fmt.Sprintf("default-%s", runtime.GOOS)
}

func (d *defaultSyscaller) Available() bool {
	return false
}

// newDefaultSyscaller returns the fallback implementation.
func newDefaultSyscaller() Syscaller {
	return &defaultSyscaller{}
}
