//go:build windows

package credential

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

type dataBlob struct {
	cbData uint32
	pbData *byte
}

var (
	modCrypt32             = windows.NewLazySystemDLL("crypt32.dll")
	procCryptUnprotectData = modCrypt32.NewProc("CryptUnprotectData")
)

// UnprotectDPAPI decrypts a DPAPI blob in the current user's context (or the
// machine context when machine is true). It is used for values copied from
// credential stores; it does not parse any store itself.
func UnprotectDPAPI(blob, entropy []byte, machine bool) ([]byte, error) {
	if len(blob) == 0 {
		return nil, fmt.Errorf("DPAPI blob is empty")
	}
	in := dataBlob{cbData: uint32(len(blob)), pbData: &blob[0]}
	var ent *dataBlob
	if len(entropy) > 0 {
		ent = &dataBlob{cbData: uint32(len(entropy)), pbData: &entropy[0]}
	}
	var out dataBlob
	var flags uintptr
	if machine {
		flags = 0x4 // CRYPTPROTECT_LOCAL_MACHINE
	}
	ret, _, callErr := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&in)),
		0,
		uintptr(unsafe.Pointer(ent)),
		0,
		0,
		flags,
		uintptr(unsafe.Pointer(&out)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("CryptUnprotectData: %w", callErr)
	}
	defer func() {
		if out.pbData != nil {
			_, _ = windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(out.pbData))))
		}
	}()
	if out.cbData == 0 || out.pbData == nil {
		return nil, fmt.Errorf("CryptUnprotectData returned no data")
	}
	plain := make([]byte, int(out.cbData))
	copy(plain, unsafe.Slice(out.pbData, int(out.cbData)))
	return plain, nil
}
