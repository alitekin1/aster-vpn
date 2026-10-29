package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"unsafe"

	"aster/windows/internal/app"
	"aster/windows/internal/platform"
	"aster/windows/ui"
	webview "github.com/jchv/go-webview2"
	"github.com/jchv/go-webview2/webviewloader"
	"golang.org/x/sys/windows"
)

func main() {
	runtime.LockOSThread()
	mutex, ok := platform.SingleInstance()
	if !ok {
		platform.Message("Aster is already running. Open it from the system tray.")
		return
	}
	defer windows.CloseHandle(mutex)
	exe, e := os.Executable()
	if e != nil {
		platform.Message("Cannot locate the application folder.")
		return
	}
	dir := filepath.Dir(exe)
	// Restrict DLL search to the executable directory and Windows system files.
	_ = windows.SetDefaultDllDirectories(windows.LOAD_LIBRARY_SEARCH_APPLICATION_DIR | windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
	data, e := app.DataDirectory()
	if e != nil {
		platform.Message("Cannot locate your settings folder.")
		return
	}
	if e = os.MkdirAll(data, 0700); e != nil {
		platform.Message("Cannot create your settings folder.")
		return
	}
	a, e := app.New(data, filepath.Join(dir, "GeoData"))
	if e != nil {
		platform.Message(e.Error())
		return
	}
	defer a.Close()
	if _, e := webviewloader.GetInstalledVersion(); e != nil {
		platform.Message("Aster needs Microsoft Edge WebView2 Runtime. Run Install-WebView2.ps1 in this folder, then open Aster again.")
		return
	}
	w := webview.NewWithOptions(webview.WebViewOptions{Debug: false, DataPath: filepath.Join(data, "WebView2"), AutoFocus: true, WindowOptions: webview.WindowOptions{Title: "Aster", Width: 1120, Height: 820, Center: true, IconId: 1}})
	if w == nil {
		platform.Message("Aster needs Microsoft Edge WebView2 Runtime. Install it using Install-WebView2.ps1 in this folder, then open Aster again.")
		return
	}
	defer w.Destroy()
	w.SetSize(960, 660, webview.HintMin)
	var once sync.Once
	quit := func() { once.Do(func() { go func() { a.Close(); w.Dispatch(func() { w.Terminate() }) }() }) }
	shell := platform.NewWindowShell(uintptr(unsafe.Pointer(w.Window())), func() { _, _ = a.Command("toggle", json.RawMessage(`{}`)) }, quit, func() bool { return a.Snapshot().Connected })
	defer shell.Close()
	shell.OnVisibility = func(visible bool) {
		if visible {
			w.Eval("window.asterVisibility && window.asterVisibility(true)")
		} else {
			w.Eval("window.asterVisibility && window.asterVisibility(false)")
		}
	}
	a.Quit = quit
	a.Minimize = shell.Hide
	a.Export = shell.Export
	if e = w.Bind("aster", a.Command); e != nil {
		platform.Message("Cannot initialize the application interface.")
		return
	}
	w.SetHtml(ui.HTML())
	a.StartBackground()
	w.Run()
}
