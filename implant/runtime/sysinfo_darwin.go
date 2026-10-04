//go:build darwin

package runtime

import (
	"net"
	"os"
	"os/user"
	"runtime"
)

type darwinCollector struct{}

// NewCollector returns the macOS/Darwin system info collector.
func NewCollector() Collector {
	return &darwinCollector{}
}

func (c *darwinCollector) Collect() (*SystemInfo, error) {
	hostname, _ := os.Hostname()

	u, _ := user.Current()
	username := ""
	uid := ""
	if u != nil {
		username = u.Username
		uid = u.Uid
	}

	ips := collectDarwinIPs()

	integrity := "medium"
	if uid == "0" {
		integrity = "high"
	}

	return &SystemInfo{
		Hostname:    hostname,
		OS:          runtime.GOOS,
		Arch:        runtime.GOARCH,
		Username:    username,
		UserID:      uid,
		ProcessID:   os.Getpid(),
		ProcessName: darwinProcName(),
		InternalIPs: ips,
		Integrity:   integrity,
	}, nil
}

func collectDarwinIPs() []string {
	var ips []string
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ips
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To4() != nil || ipNet.IP.To16() != nil {
				ips = append(ips, ipNet.IP.String())
			}
		}
	}
	return ips
}

func darwinProcName() string {
	path, err := os.Executable()
	if err != nil {
		return "unknown"
	}
	return path
}
