package platform

import (
	"fmt"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"unsafe"

	"aster/windows/internal/core"
	"github.com/lxn/win"
	"golang.org/x/sys/windows"
)

const trayMessage = win.WM_APP + 46

// WindowShell uses the existing WebView message loop for native tray callbacks.
// Closing hides the window; only Quit exits and releases capture.
type WindowShell struct {
	OnVisibility func(bool)
	hwnd         win.HWND
	previous     uintptr
	callback     uintptr
	notify       win.NOTIFYICONDATA
	quitting     atomic.Bool
	Toggle       func()
	Quit         func()
	Connected    func() bool
	Show         func()
	taskbar      uint32
	onResume     func()
}

func NewWindowShell(hwnd uintptr, toggle, quit func(), connected func() bool) *WindowShell {
	s := &WindowShell{hwnd: win.HWND(hwnd), Toggle: toggle, Quit: quit, Connected: connected}
	s.Show = func() { win.ShowWindow(s.hwnd, win.SW_RESTORE); win.SetForegroundWindow(s.hwnd) }
	s.callback = syscall.NewCallback(s.wndproc)
	s.previous = win.SetWindowLongPtr(s.hwnd, win.GWLP_WNDPROC, s.callback)
	icon := win.LoadIcon(win.GetModuleHandle(nil), win.MAKEINTRESOURCE(1))
	s.notify = win.NOTIFYICONDATA{HWnd: s.hwnd, UID: 1, UFlags: win.NIF_MESSAGE | win.NIF_ICON | win.NIF_TIP, UCallbackMessage: trayMessage, HIcon: icon}
	s.notify.CbSize = uint32(unsafe.Sizeof(s.notify))
	copy(s.notify.SzTip[:], syscall.StringToUTF16("Aster — Your traffic. Your rules."))
	s.taskbar = win.RegisterWindowMessage(syscall.StringToUTF16Ptr("TaskbarCreated"))
	win.Shell_NotifyIcon(win.NIM_ADD, &s.notify)
	return s
}
func (s *WindowShell) wndproc(hwnd win.HWND, msg uint32, wp, lp uintptr) uintptr {
	switch msg {
	case win.WM_SHOWWINDOW:
		if s.OnVisibility != nil {
			s.OnVisibility(wp != 0)
		}
	case win.WM_SIZE:
		if s.OnVisibility != nil {
			s.OnVisibility(wp != 1 /* SIZE_MINIMIZED */ && win.IsWindowVisible(s.hwnd))
		}
	case win.WM_CLOSE:
		if !s.quitting.Load() {
			s.Hide()
			return 0
		}
	case win.WM_APP + 48:
		return 0x41535452 // Installer handshake (ASTR).
	case win.WM_APP + 47: // Installer requests graceful shutdown, including tunnel cleanup.
		if s.Quit != nil {
			s.Quit()
		}
		return 0
	case win.WM_QUERYENDSESSION:
		if s.Quit != nil {
			s.Quit()
		}
		return 1
	case trayMessage:
		if lp == win.WM_LBUTTONUP || lp == win.WM_LBUTTONDBLCLK {
			s.Show()
		} else if lp == win.WM_RBUTTONUP {
			s.menu()
		}
		return 0
	default:
		if msg == s.taskbar {
			win.Shell_NotifyIcon(win.NIM_ADD, &s.notify)
			return 0
		}
	}
	return win.CallWindowProc(s.previous, hwnd, msg, wp, lp)
}
func (s *WindowShell) Hide() { win.ShowWindow(s.hwnd, win.SW_HIDE) }
func (s *WindowShell) Close() {
	s.quitting.Store(true)
	win.Shell_NotifyIcon(win.NIM_DELETE, &s.notify)
	win.SetWindowLongPtr(s.hwnd, win.GWLP_WNDPROC, s.previous)
}
func (s *WindowShell) menu() {
	m := win.CreatePopupMenu()
	defer win.DestroyMenu(m)
	items := []string{"Open Aster", "Connect", "Quit Aster"}
	if s.Connected() {
		items[1] = "Disconnect"
	}
	for i, text := range items {
		v := win.MENUITEMINFO{CbSize: uint32(unsafe.Sizeof(win.MENUITEMINFO{})), FMask: win.MIIM_ID | win.MIIM_STRING, WID: uint32(i + 1), DwTypeData: syscall.StringToUTF16Ptr(text)}
		win.InsertMenuItem(m, uint32(i), true, &v)
	}
	var p win.POINT
	win.GetCursorPos(&p)
	win.SetForegroundWindow(s.hwnd)
	id := win.TrackPopupMenu(m, win.TPM_RETURNCMD|win.TPM_RIGHTBUTTON, p.X, p.Y, 0, s.hwnd, nil)
	switch id {
	case 1:
		s.Show()
	case 2:
		s.Toggle()
	case 3:
		s.Quit()
	}
}
func (s *WindowShell) Export(text string) error {
	buf := make([]uint16, 32768)
	copy(buf, syscall.StringToUTF16("Aster-diagnostics.json"))
	filter := []uint16{}
	for _, v := range []string{"JSON diagnostics (*.json)", "*.json", ""} {
		filter = append(filter, syscall.StringToUTF16(v)...)
	}
	ext := syscall.StringToUTF16Ptr("json")
	f := win.OPENFILENAME{LStructSize: uint32(unsafe.Sizeof(win.OPENFILENAME{})), HwndOwner: s.hwnd, LpstrFilter: &filter[0], LpstrFile: &buf[0], NMaxFile: uint32(len(buf)), LpstrDefExt: ext, Flags: win.OFN_OVERWRITEPROMPT | win.OFN_PATHMUSTEXIST | win.OFN_NOCHANGEDIR}
	if !win.GetSaveFileName(&f) {
		if win.CommDlgExtendedError() != 0 {
			return fmt.Errorf("could not open export dialog")
		}
		return nil
	}
	path := syscall.UTF16ToString(buf)
	if filepath.Ext(path) == "" {
		path += ".json"
	}
	return core.AtomicWrite(path, []byte(text))
}
func Message(text string) {
	win.MessageBox(0, syscall.StringToUTF16Ptr(text), syscall.StringToUTF16Ptr("Aster"), win.MB_OK|win.MB_ICONERROR)
}
func SingleInstance() (windows.Handle, bool) {
	h, e := windows.CreateMutex(nil, false, syscall.StringToUTF16Ptr("Local\\Aster.Windows.Desktop"))
	if e == windows.ERROR_ALREADY_EXISTS {
		return h, false
	}
	return h, e == nil
}
