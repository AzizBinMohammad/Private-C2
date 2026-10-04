//go:build windows

package runtime

import (
	"net"
	"os"
	"os/user"
	"runtime"
)

type windowsCollector struct{}

// NewCollector returns the Windows system info collector.
func NewCollector() Collector {
	return &windowsCollector{}
}

func (c *windowsCollector) Collect() (*SystemInfo, error) {
	hostname, _ := os.Hostname()

	u, _ := user.Current()
	username := ""
	uid := ""
	if u != nil {
		username = u.Username
		uid = u.Uid
	}

	ips := collectWindowsIPs()

	// On Windows, a rough integrity check: administrators typically have
	// well-known SIDs. This is a placeholder; real detection would use
	// Windows API calls to check token elevation.
	integrity := "medium"

	return &SystemInfo{
		Hostname:    hostname,
		OS:          runtime.GOOS,
		Arch:        runtime.GOARCH,
		Username:    username,
		UserID:      uid,
		ProcessID:   os.Getpid(),
		ProcessName: windowsProcName(),
		InternalIPs: ips,
		Integrity:   integrity,
	}, nil
}

func collectWindowsIPs() []string {
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

func windowsProcName() string {
	path, err := os.Executable()
	if err != nil {
		return "unknown"
	}
	return path
}
