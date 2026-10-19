//go:build !windows

package pivot

import "fmt"

// NamedPipeProxy is only available on Windows.
type NamedPipeProxy struct{}

// StartNamedPipeProxy reports that named pipes require Windows.
func StartNamedPipeProxy(string, string, ScopeCheck) (*NamedPipeProxy, error) {
	return nil, fmt.Errorf("named-pipe pivots require Windows")
}

func (p *NamedPipeProxy) Addr() string { return "" }

func (p *NamedPipeProxy) Close() error { return nil }
