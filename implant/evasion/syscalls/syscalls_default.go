//go:build !windows

package syscalls

func newPlatformSyscaller() Syscaller {
	return newDefaultSyscaller()
}
