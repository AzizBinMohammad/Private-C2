//go:build !windows && !linux && !darwin

package logs

func NewClearer() LogClearer {
	return newGenericClearer()
}
