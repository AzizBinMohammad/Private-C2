package network

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/azizbinmohammad/private-c2/pkg/engagement"
)

// Operation defines the network operation type.
type Operation string

const (
	OpIfconfig Operation = "ifconfig"
	OpNetstat  Operation = "netstat"
	OpPortscan Operation = "portscan"
	OpResolve  Operation = "resolve"
)

// Request represents a network operation request.
type Request struct {
	Op      Operation `json:"op"`
	Target  string    `json:"target,omitempty"`   // for portscan, resolve
	Ports   []int     `json:"ports,omitempty"`    // for portscan
	Timeout int       `json:"timeout,omitempty"`  // milliseconds
}

// InterfaceInfo represents a network interface.
type InterfaceInfo struct {
	Name       string   `json:"name"`
	MTU        int      `json:"mtu"`
	Flags      string   `json:"flags"`
	HWAddr     string   `json:"hw_addr,omitempty"`
	Addresses  []string `json:"addresses"`
}

// ConnectionInfo represents a network connection.
type ConnectionInfo struct {
	Protocol  string `json:"protocol"`
	LocalAddr string `json:"local_addr"`
	RemoteAddr string `json:"remote_addr"`
	State     string `json:"state"`
}

// PortResult represents the result of scanning a single port.
type PortResult struct {
	Port   int    `json:"port"`
	Open   bool   `json:"open"`
	Banner string `json:"banner,omitempty"`
}

// ResolveResult represents DNS resolution results.
type ResolveResult struct {
	Hostname  string   `json:"hostname"`
	Addresses []string `json:"addresses"`
}

// Response represents the result of a network operation.
type Response struct {
	Output      string           `json:"output,omitempty"`
	Interfaces  []InterfaceInfo  `json:"interfaces,omitempty"`
	Connections []ConnectionInfo `json:"connections,omitempty"`
	Ports       []PortResult     `json:"ports,omitempty"`
	Resolved    *ResolveResult   `json:"resolved,omitempty"`
}

// Module provides network operations with scope checking.
type Module struct {
	scope *engagement.Scope
}

// NewModule creates a new network module with optional scope checking.
func NewModule(scope *engagement.Scope) *Module {
	return &Module{scope: scope}
}

// Execute handles a network operation request.
func (m *Module) Execute(ctx context.Context, payload []byte) ([]byte, error) {
	var req Request
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, fmt.Errorf("parsing network request: %w", err)
	}

	var resp *Response
	var err error

	switch req.Op {
	case OpIfconfig:
		resp, err = m.ifconfig()
	case OpNetstat:
		resp, err = m.netstat(ctx)
	case OpPortscan:
		resp, err = m.portscan(ctx, req)
	case OpResolve:
		resp, err = m.resolve(ctx, req.Target)
	default:
		return nil, fmt.Errorf("unknown network operation: %s", req.Op)
	}

	if err != nil {
		return nil, err
	}

	return json.Marshal(resp)
}

// ifconfig lists network interfaces and their addresses.
func (m *Module) ifconfig() (*Response, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("listing interfaces: %w", err)
	}

	var infos []InterfaceInfo
	for _, iface := range ifaces {
		info := InterfaceInfo{
			Name:   iface.Name,
			MTU:    iface.MTU,
			Flags:  iface.Flags.String(),
			HWAddr: iface.HardwareAddr.String(),
		}

		addrs, err := iface.Addrs()
		if err == nil {
			for _, addr := range addrs {
				info.Addresses = append(info.Addresses, addr.String())
			}
		}

		infos = append(infos, info)
	}

	return &Response{Interfaces: infos}, nil
}

// netstat shows active network connections using platform tools.
func (m *Module) netstat(ctx context.Context) (*Response, error) {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "linux":
		cmd = exec.CommandContext(ctx, "ss", "-tunap")
	case "darwin":
		cmd = exec.CommandContext(ctx, "netstat", "-an", "-p", "tcp")
	case "windows":
		cmd = exec.CommandContext(ctx, "netstat", "-an")
	default:
		cmd = exec.CommandContext(ctx, "netstat", "-an")
	}

	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("running netstat: %w", err)
	}

	return &Response{Output: string(output)}, nil
}

// portscan performs a TCP port scan with scope validation.
func (m *Module) portscan(ctx context.Context, req Request) (*Response, error) {
	if req.Target == "" {
		return nil, fmt.Errorf("target is required for port scan")
	}

	// Check scope before scanning.
	if m.scope != nil {
		inScope, reason := m.scope.Contains(req.Target)
		if !inScope {
			return nil, fmt.Errorf("port scan blocked: %s", reason)
		}
	}

	ports := req.Ports
	if len(ports) == 0 {
		// Default common ports.
		ports = []int{21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
			993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443}
	}

	timeout := time.Duration(req.Timeout) * time.Millisecond
	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	results := make([]PortResult, len(ports))
	var wg sync.WaitGroup

	// Limit concurrency for port scanning.
	sem := make(chan struct{}, 50)

	for i, port := range ports {
		wg.Add(1)
		go func(idx, p int) {
			defer wg.Done()

			sem <- struct{}{}
			defer func() { <-sem }()

			result := PortResult{Port: p}
			addr := fmt.Sprintf("%s:%d", req.Target, p)

			conn, err := net.DialTimeout("tcp", addr, timeout)
			if err == nil {
				result.Open = true

				// Try to grab a banner.
				conn.SetReadDeadline(time.Now().Add(1 * time.Second))
				banner := make([]byte, 256)
				n, _ := conn.Read(banner)
				if n > 0 {
					result.Banner = strings.TrimSpace(string(banner[:n]))
				}
				conn.Close()
			}

			results[idx] = result
		}(i, port)
	}

	wg.Wait()

	return &Response{Ports: results}, nil
}

// resolve performs DNS resolution for a hostname.
func (m *Module) resolve(ctx context.Context, target string) (*Response, error) {
	if target == "" {
		return nil, fmt.Errorf("target hostname is required for resolve")
	}

	resolver := &net.Resolver{}
	addrs, err := resolver.LookupHost(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("resolving %s: %w", target, err)
	}

	return &Response{
		Resolved: &ResolveResult{
			Hostname:  target,
			Addresses: addrs,
		},
	}, nil
}
