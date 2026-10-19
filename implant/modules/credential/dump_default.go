//go:build !windows

package credential

// Dump is only available on Windows; other targets report a clear error.
func Dump(string) (DumpResult, error) {
	return DumpResult{}, ErrDumpUnsupported
}
