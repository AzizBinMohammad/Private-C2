package stealth

import (
	"os"
	"runtime"
)

type TraceCleanup struct {
	profile Profile
}

func NewTraceCleanup(profile Profile) *TraceCleanup {
	return &TraceCleanup{profile: profile}
}

func (tc *TraceCleanup) CleanEnvironment() []string {
	var cleaned []string

	envVarsToRemove := []string{
		"HISTFILE",
		"HISTSIZE",
		"HISTFILESIZE",
		"PROMPT_COMMAND",
	}

	if runtime.GOOS != "windows" {
		for _, env := range envVarsToRemove {
			if _, exists := os.LookupEnv(env); exists {
				os.Unsetenv(env)
				cleaned = append(cleaned, env)
			}
		}

		os.Setenv("HISTSIZE", "0")
		os.Setenv("HISTFILESIZE", "0")
	}

	return cleaned
}

func (tc *TraceCleanup) SelfCleanPaths() []string {
	switch runtime.GOOS {
	case "linux":
		return []string{
			"/tmp",
			"/var/tmp",
			"/dev/shm",
		}
	case "darwin":
		return []string{
			"/tmp",
			"/private/tmp",
		}
	case "windows":
		return []string{
			os.Getenv("TEMP"),
			os.Getenv("TMP"),
		}
	default:
		return []string{"/tmp"}
	}
}

func (tc *TraceCleanup) RemoveSelfBinary(binaryPath string) error {
	if tc.profile < ProfileParanoid {
		return nil
	}
	return os.Remove(binaryPath)
}
