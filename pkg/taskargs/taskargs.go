// Package taskargs parses the string arguments carried by task types so the
// server and implant agree on which target, if any, a task will act on.
package taskargs

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/azizbinmohammad/private-c2/pkg/protocol"
)

// ParsePortscan accepts "target" or "target:22,80,443".
func ParsePortscan(args string) (target string, ports []int, err error) {
	args = strings.TrimSpace(args)
	if args == "" {
		return "", nil, fmt.Errorf("portscan requires a target")
	}
	target = args
	if i := strings.LastIndex(args, ":"); i > 0 && i < len(args)-1 {
		suffix := args[i+1:]
		if portList, err := ParsePorts(suffix); err == nil {
			target = args[:i]
			ports = portList
		}
	}
	if target == "" {
		return "", nil, fmt.Errorf("portscan target is empty")
	}
	return target, ports, nil
}

// ParsePorts parses a comma-separated port list.
func ParsePorts(s string) ([]int, error) {
	fields := strings.Split(s, ",")
	ports := make([]int, 0, len(fields))
	for _, f := range fields {
		p, err := strconv.Atoi(strings.TrimSpace(f))
		if err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("invalid port %q", f)
		}
		ports = append(ports, p)
	}
	return ports, nil
}

// Target extracts the network target a task will act on, when it has one.
// Unknown or non-network task types return "".
func Target(taskType, args string) string {
	switch taskType {
	case protocol.TaskPortscan:
		target, _, err := ParsePortscan(args)
		if err == nil {
			return target
		}
	case protocol.TaskResolve:
		return strings.TrimSpace(args)
	case protocol.TaskScan:
		var req struct {
			Target string `json:"target"`
		}
		if err := json.Unmarshal([]byte(args), &req); err == nil {
			return strings.TrimSpace(req.Target)
		}
	case protocol.TaskNmap:
		fields := strings.Fields(args)
		for i := len(fields) - 1; i >= 0; i-- {
			if !strings.HasPrefix(fields[i], "-") {
				return fields[i]
			}
		}
	}
	return ""
}
