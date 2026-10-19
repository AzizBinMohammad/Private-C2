//go:build !windows

package token

type unsupportedManager struct{}

func newPlatformManager() Manager { return &unsupportedManager{} }

func (m *unsupportedManager) List() ([]Info, error) { return nil, ErrUnsupported }

func (m *unsupportedManager) Steal(int) (Info, error) { return Info{}, ErrUnsupported }

func (m *unsupportedManager) Make(string, string, string, string) (Info, error) {
	return Info{}, ErrUnsupported
}

func (m *unsupportedManager) Impersonate(string) (Info, error) { return Info{}, ErrUnsupported }

func (m *unsupportedManager) Revert() (int, error) { return 0, ErrUnsupported }

func (m *unsupportedManager) Privileges() ([]Privilege, error) { return nil, ErrUnsupported }

func (m *unsupportedManager) Close() error { return nil }
