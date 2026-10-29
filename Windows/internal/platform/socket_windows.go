package platform

import (
	"encoding/binary"
	"golang.org/x/sys/windows"
	"net"
	"strings"
	"syscall"
	"unsafe"
)

func bindControl(name string) func(string, string, syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		iface, e := net.InterfaceByName(name)
		if e != nil {
			return e
		}
		var bindErr error
		e = c.Control(func(fd uintptr) {
			host, _, _ := net.SplitHostPort(address)
			if strings.Contains(host, ":") {
				bindErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, 31, iface.Index)
			} else {
				var b [4]byte
				binary.BigEndian.PutUint32(b[:], uint32(iface.Index))
				bindErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, 31, int(*(*uint32)(unsafe.Pointer(&b[0]))))
			}
		})
		if e != nil {
			return e
		}
		return bindErr
	}
}
