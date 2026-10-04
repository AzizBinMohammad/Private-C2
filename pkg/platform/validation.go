package platform

import (
	"fmt"
	"slices"
	"strings"
)

type ValidationError struct {
	Code    string
	Message string
	Details map[string]any
}

func (e *ValidationError) Error() string {
	return e.Message
}

type ValidationResult struct {
	Valid    bool
	Errors  []ValidationError
	Warnings []string
}

func ValidatePayloadConfig(os, arch, mode string, transports, features []string) ValidationResult {
	result := ValidationResult{Valid: true}

	caps, supported := GetCapabilities(os, arch)
	if !supported {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Code:    "UNSUPPORTED_PLATFORM",
			Message: fmt.Sprintf("platform %s/%s is not supported", os, arch),
			Details: map[string]any{
				"requested_os":   os,
				"requested_arch": arch,
				"supported_os":   SupportedOperatingSystems(),
				"supported_arch": SupportedArchitectures(os),
			},
		})
		return result
	}

	if !slices.Contains(caps.ImplantModes, mode) {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Code:    "UNSUPPORTED_MODE",
			Message: fmt.Sprintf("implant mode %q is not supported on %s/%s", mode, os, arch),
			Details: map[string]any{
				"supported_modes": caps.ImplantModes,
			},
		})
	}

	for _, t := range transports {
		if !slices.Contains(caps.Transports, strings.ToLower(t)) {
			result.Valid = false
			result.Errors = append(result.Errors, ValidationError{
				Code:    "UNSUPPORTED_TRANSPORT",
				Message: fmt.Sprintf("transport %q is not available on %s/%s", t, os, arch),
				Details: map[string]any{
					"supported_transports": caps.Transports,
				},
			})
		}
	}

	for _, f := range features {
		if !slices.Contains(caps.Features, strings.ToLower(f)) {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("feature %q is not available on %s/%s and will be disabled", f, os, arch))
		}
	}

	return result
}
