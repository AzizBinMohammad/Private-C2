package lateral

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// WinRMRequest describes a PowerShell Remoting or WMI execution request.
type WinRMRequest struct {
	Target   string `json:"target"`
	Username string `json:"username"`
	Password string `json:"password"`
	Command  string `json:"command"`
	Port     int    `json:"port,omitempty"`
	UseSSL   bool   `json:"use_ssl,omitempty"`
}

// ParseWinRMRequest validates a lateral_winrm argument object.
func ParseWinRMRequest(args string) (WinRMRequest, error) {
	return parseRemote(args, 5985)
}

// ParseWMIRequest validates a lateral_wmi argument object.
func ParseWMIRequest(args string) (WinRMRequest, error) {
	return parseRemote(args, 0)
}

func parseRemote(args string, defaultPort int) (WinRMRequest, error) {
	var req WinRMRequest
	if err := json.Unmarshal([]byte(args), &req); err != nil {
		return req, fmt.Errorf("args must be JSON: %w", err)
	}
	req.Target = strings.TrimSpace(req.Target)
	req.Username = strings.TrimSpace(req.Username)
	req.Command = strings.TrimSpace(req.Command)
	if req.Target == "" {
		return req, fmt.Errorf("target is required")
	}
	if req.Username == "" {
		return req, fmt.Errorf("username is required")
	}
	if req.Password == "" {
		return req, fmt.Errorf("password is required")
	}
	if req.Command == "" {
		return req, fmt.Errorf("command is required")
	}
	if req.Port == 0 {
		req.Port = defaultPort
	}
	if req.Port < 0 || req.Port > 65535 {
		return req, fmt.Errorf("port %d is out of range", req.Port)
	}
	return req, nil
}

func psQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func credentialPrelude(req WinRMRequest) string {
	return "$sec=ConvertTo-SecureString " + psQuote(req.Password) + " -AsPlainText -Force; " +
		"$cred=New-Object System.Management.Automation.PSCredential(" + psQuote(req.Username) + ",$sec); "
}

// WinRMScript builds the PowerShell Remoting invocation. The password is part
// of the encoded command, never an argv element.
func WinRMScript(req WinRMRequest) string {
	script := credentialPrelude(req) +
		"Invoke-Command -ComputerName " + psQuote(req.Target) +
		" -Port " + strconv.Itoa(req.Port) + " -Credential $cred"
	if req.UseSSL {
		script += " -UseSSL"
	}
	script += " -ScriptBlock ([ScriptBlock]::Create(" + psQuote(req.Command) + "))"
	return script
}

// WMIScript builds a Win32_Process Create call. WMI does not return process
// output; the result includes the remote process ID on success.
func WMIScript(req WinRMRequest) string {
	return credentialPrelude(req) +
		"Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList " +
		psQuote(req.Command) + " -ComputerName " + psQuote(req.Target) +
		" -Credential $cred"
}
