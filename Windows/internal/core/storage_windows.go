package core

import (
	"golang.org/x/sys/windows"
	"os"
	"unsafe"
)

func replaceFile(from, to string) error {
	a, e := windows.UTF16PtrFromString(from)
	if e != nil {
		return e
	}
	b, e := windows.UTF16PtrFromString(to)
	if e != nil {
		return e
	}
	return windows.MoveFileEx(a, b, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
func protect(data []byte, encrypt bool) ([]byte, error) {
	var in windows.DataBlob
	if len(data) > 0 {
		in.Size = uint32(len(data))
		in.Data = &data[0]
	}
	var out windows.DataBlob
	var err error
	if encrypt {
		err = windows.CryptProtectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	} else {
		err = windows.CryptUnprotectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	}
	if err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}
func SaveState(path string, s State) error {
	raw, e := EncodeState(s)
	if e != nil {
		return e
	}
	b, e := protect(raw, true)
	if e != nil {
		return e
	}
	return AtomicWrite(path, b)
}
func LoadState(path string) (State, error) {
	b, e := os.ReadFile(path)
	if os.IsNotExist(e) {
		return DefaultState(), nil
	}
	if e != nil {
		return State{}, e
	}
	b, e = protect(b, false)
	if e != nil {
		return State{}, e
	}
	return DecodeState(b)
}
