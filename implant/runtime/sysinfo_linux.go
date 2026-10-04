//go:build linux

package runtime

import (
	"net"
	"os"
	"os/user"
	"runtime"
)

type linuxCollector struct{}

// NewCollector returns the Linux system info collector.
func NewCollector() Collector {
	return &linuxCollector{}
}

func (c *linuxCollector) Collect() (*SystemInfo, error) {
	hostname, _ := os.Hostname()

	u, _ := user.Current()
	username := ""
	uid := ""
	if u != nil {
		username = u.Username
		uid = u.Uid
	}

	ips := collectIPs()

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
		ProcessName: procName(),
		InternalIPs: ips,
		Integrity:   integrity,
	}, nil
}

func collectIPs() []string {
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

func procName() string {
	path, err := os.Executable()
	if err != nil {
		return "unknown"
	}
	return path
}
