package taskargs

import (
	"reflect"
	"testing"

	"github.com/azizbinmohammad/private-c2/pkg/protocol"
)

func TestParsePortscan(t *testing.T) {
	cases := []struct {
		args   string
		target string
		ports  []int
		ok     bool
	}{
		{"10.0.0.1", "10.0.0.1", nil, true},
		{"10.0.0.1:22,80,443", "10.0.0.1", []int{22, 80, 443}, true},
		{"host.example:8080", "host.example", []int{8080}, true},
		{"host:notaport", "host:notaport", nil, true},
		{"", "", nil, false},
	}
	for _, tc := range cases {
		target, ports, err := ParsePortscan(tc.args)
		if tc.ok {
			if err != nil || target != tc.target || !reflect.DeepEqual(ports, tc.ports) {
				t.Errorf("ParsePortscan(%q) = (%q,%v,%v), want (%q,%v,nil)", tc.args, target, ports, err, tc.target, tc.ports)
			}
		} else if err == nil {
			t.Errorf("ParsePortscan(%q) unexpectedly succeeded", tc.args)
		}
	}
}

func TestTarget(t *testing.T) {
	cases := []struct {
		taskType string
		args     string
		want     string
	}{
		{protocol.TaskPortscan, "10.0.0.5:22,80", "10.0.0.5"},
		{protocol.TaskResolve, "example.com", "example.com"},
		{protocol.TaskScan, `{"target":"10.0.0.9"}`, "10.0.0.9"},
		{protocol.TaskNmap, "-sV 10.0.0.7", "10.0.0.7"},
		{protocol.TaskShell, "whoami", ""},
	}
	for _, tc := range cases {
		if got := Target(tc.taskType, tc.args); got != tc.want {
			t.Errorf("Target(%q,%q) = %q, want %q", tc.taskType, tc.args, got, tc.want)
		}
	}
}
