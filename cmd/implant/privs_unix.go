//go:build !windows

package main

import (
	"os"
	"runtime"
	"strings"
)

type privilegeReport struct {
	UID    int    `json:"uid"`
	GID    int    `json:"gid"`
	Groups []int  `json:"groups"`
	CapEff string `json:"cap_eff,omitempty"`
	CapPrm string `json:"cap_prm,omitempty"`
	CapBnd string `json:"cap_bnd,omitempty"`
	Note   string `json:"note,omitempty"`
}

// platformPrivileges reports the Unix identity and, on Linux, the capability
// sets from /proc/self/status.
func platformPrivileges() (any, error) {
	groups, _ := os.Getgroups()
	report := privilegeReport{UID: os.Getuid(), GID: os.Getgid(), Groups: groups}
	if runtime.GOOS != "linux" {
		report.Note = "capability sets are Linux-only"
		return report, nil
	}

	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		report.Note = "could not read /proc/self/status: " + err.Error()
		return report, nil
	}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch key {
		case "CapEff":
			report.CapEff = strings.TrimSpace(value)
		case "CapPrm":
			report.CapPrm = strings.TrimSpace(value)
		case "CapBnd":
			report.CapBnd = strings.TrimSpace(value)
		}
	}
	return report, nil
}
