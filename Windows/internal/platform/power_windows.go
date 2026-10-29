package platform

import (
	"golang.org/x/sys/windows"
	"unsafe"
)

func LowPower() bool {
	var status struct {
		AC      byte
		Battery byte
		Percent byte
		Saver   byte
		Life    uint32
		Full    uint32
	}
	r, _, _ := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetSystemPowerStatus").Call(uintptr(unsafe.Pointer(&status)))
	return r != 0 && status.Saver == 1
}
