//go:build windows

package spawn

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// SpoofParent starts command with parentPID recorded as its parent by using
// PROC_THREAD_ATTRIBUTE_PARENT_PROCESS. The caller must already hold the
// privilege needed to open the chosen parent.
func SpoofParent(command string, parentPID uint32) (Result, error) {
	command = strings.TrimSpace(command)
	if command == "" {
		return Result{}, fmt.Errorf("command is required")
	}
	if parentPID == 0 {
		return Result{}, fmt.Errorf("parent PID is required")
	}

	parent, err := windows.OpenProcess(windows.PROCESS_CREATE_PROCESS, false, parentPID)
	if err != nil {
		return Result{}, fmt.Errorf("opening parent process %d: %w", parentPID, err)
	}
	defer windows.CloseHandle(parent)

	attributes, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return Result{}, fmt.Errorf("allocating process attributes: %w", err)
	}
	defer attributes.Delete()
	if err := attributes.Update(windows.PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
		unsafe.Pointer(&parent), unsafe.Sizeof(parent)); err != nil {
		return Result{}, fmt.Errorf("setting parent process: %w", err)
	}

	var startup windows.StartupInfoEx
	startup.ProcThreadAttributeList = attributes.List()
	startup.Cb = uint32(unsafe.Sizeof(startup))
	var processInfo windows.ProcessInformation

	cmdLine, err := windows.UTF16PtrFromString(command)
	if err != nil {
		return Result{}, err
	}
	flags := uint32(windows.EXTENDED_STARTUPINFO_PRESENT | windows.CREATE_NEW_CONSOLE)
	if err := windows.CreateProcess(nil, cmdLine, nil, nil, false, flags,
		nil, nil, &startup.StartupInfo, &processInfo); err != nil {
		return Result{}, fmt.Errorf("CreateProcess: %w", err)
	}
	defer windows.CloseHandle(processInfo.Process)
	defer windows.CloseHandle(processInfo.Thread)

	return Result{PID: processInfo.ProcessId, ParentPID: parentPID, Command: command}, nil
}
