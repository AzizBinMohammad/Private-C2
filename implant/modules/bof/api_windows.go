//go:build windows

package bof

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const maxFormatSize = 1 << 20

// buildImports returns the Beacon API subset implemented by this loader. The
// callbacks use syscall.NewCallback, which gives the BOF the Windows x64 ABI it
// expects. Unsupported Beacon* imports are left unresolved so the loader
// reports the exact missing symbol instead of silently failing.
func buildImports(collector *OutputCollector) map[string]uintptr {
	return map[string]uintptr{
		"BeaconOutput": syscall.NewCallback(func(_ uintptr, data, length uintptr) uintptr {
			collector.appendString("output", unsafe.Pointer(data), int32(length))
			return 0
		}),
		"BeaconError": syscall.NewCallback(func(_ uintptr, data, length uintptr) uintptr {
			collector.appendString("error", unsafe.Pointer(data), int32(length))
			return 0
		}),
		"BeaconDataParse": syscall.NewCallback(func(parser, buffer, length uintptr) uintptr {
			if parser != 0 {
				dataParse((*dataParser)(unsafe.Pointer(parser)), unsafe.Pointer(buffer), int32(length))
			}
			return 0
		}),
		"BeaconDataExtract": syscall.NewCallback(func(parser, sizeOut uintptr) uintptr {
			if parser == 0 {
				return 0
			}
			ptr, n := dataExtract((*dataParser)(unsafe.Pointer(parser)))
			if sizeOut != 0 {
				*(*int32)(unsafe.Pointer(sizeOut)) = n
			}
			return uintptr(ptr)
		}),
		"BeaconDataInt": syscall.NewCallback(func(parser uintptr) uintptr {
			if parser == 0 {
				return 0
			}
			return uintptr(uint32(dataInt((*dataParser)(unsafe.Pointer(parser)))))
		}),
		"BeaconDataShort": syscall.NewCallback(func(parser uintptr) uintptr {
			if parser == 0 {
				return 0
			}
			return uintptr(uint16(dataShort((*dataParser)(unsafe.Pointer(parser)))))
		}),
		"BeaconDataLength": syscall.NewCallback(func(parser uintptr) uintptr {
			if parser == 0 {
				return 0
			}
			return uintptr(uint32(dataRemaining((*dataParser)(unsafe.Pointer(parser)))))
		}),
		"BeaconIsAdmin": syscall.NewCallback(func() uintptr {
			return currentTokenElevated()
		}),
		"BeaconFormatAlloc": syscall.NewCallback(func(format, maxSize uintptr) uintptr {
			if format == 0 || maxSize == 0 || maxSize > maxFormatSize {
				return 0
			}
			mem, err := windows.LocalAlloc(0, uint32(maxSize))
			if err != nil || mem == 0 {
				return 0
			}
			formatInit((*formatBuffer)(unsafe.Pointer(format)), unsafe.Pointer(mem), int32(maxSize))
			return 0
		}),
		"BeaconFormatAppend": syscall.NewCallback(func(format, data, length uintptr) uintptr {
			if format != 0 {
				formatAppend((*formatBuffer)(unsafe.Pointer(format)), unsafe.Pointer(data), int32(length))
			}
			return 0
		}),
		"BeaconFormatToString": syscall.NewCallback(func(format, sizeOut uintptr) uintptr {
			if format == 0 {
				return 0
			}
			ptr, n := formatToString((*formatBuffer)(unsafe.Pointer(format)))
			if sizeOut != 0 {
				*(*int32)(unsafe.Pointer(sizeOut)) = n
			}
			return uintptr(ptr)
		}),
		"BeaconFormatReset": syscall.NewCallback(func(format uintptr) uintptr {
			if format != 0 {
				formatReset((*formatBuffer)(unsafe.Pointer(format)))
			}
			return 0
		}),
		"BeaconFormatFree": syscall.NewCallback(func(format uintptr) uintptr {
			if format == 0 {
				return 0
			}
			f := (*formatBuffer)(unsafe.Pointer(format))
			if f.Original != nil {
				_, _ = windows.LocalFree(windows.Handle(f.Original))
			}
			f.Original = nil
			f.Buffer = nil
			f.Length = 0
			f.Size = 0
			return 0
		}),
		"BeaconRevertToken": syscall.NewCallback(func() uintptr {
			_ = windows.RevertToSelf()
			return 0
		}),
		"BeaconGetSpawnTo": syscall.NewCallback(func(_ uintptr, _ uintptr) uintptr {
			return 0
		}),
		"BeaconUseToken": syscall.NewCallback(func(_ uintptr) uintptr {
			return 0
		}),
	}
}

func currentTokenElevated() uintptr {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return 0
	}
	defer token.Close()
	var elevated uint32
	var returned uint32
	err := windows.GetTokenInformation(token, windows.TokenElevation,
		(*byte)(unsafe.Pointer(&elevated)), uint32(unsafe.Sizeof(elevated)), &returned)
	if err != nil {
		return 0
	}
	if elevated != 0 {
		return 1
	}
	return 0
}
