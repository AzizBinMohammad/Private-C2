//go:build !linux && !windows && !darwin

package runtime

import (
	"net"
	"os"
	"os/user"
	"runtime"
)

type defaultCollector struct{}

// NewCollector returns a fallback system info collector for unsupported platforms.
func NewCollector() Collector {
	return &defaultCollector{}
}

func (c *defaultCollector) Collect() (*SystemInfo, error) {
	hostname, _ := os.Hostname()

	u, _ := user.Current()
	username := ""
	uid := ""
	if u != nil {
		username = u.Username
		uid = u.Uid
	}

	ips := collectDefaultIPs()

	return &SystemInfo{
		Hostname:    hostname,
		OS:          runtime.GOOS,
		Arch:        runtime.GOARCH,
		Username:    username,
		UserID:      uid,
		ProcessID:   os.Getpid(),
		ProcessName: defaultProcName(),
		InternalIPs: ips,
		Integrity:   "medium",
	}, nil
}

func collectDefaultIPs() []string {
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

func defaultProcName() string {
	path, err := os.Executable()
	if err != nil {
		return "unknown"
	}
	return path
}
