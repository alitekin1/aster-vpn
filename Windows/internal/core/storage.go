package core

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Secrets and subscription URLs are excluded from every UI snapshot. The entire
// disk payload is protected with per-user DPAPI on Windows.
type diskState struct {
	State     State             `json:"state"`
	Outbounds map[string]Object `json:"outbounds"`
	URLs      map[string]string `json:"urls"`
}

func EncodeState(s State) ([]byte, error) {
	d := diskState{s, map[string]Object{}, map[string]string{}}
	for _, v := range s.Servers {
		d.Outbounds[v.ID] = v.Outbound
	}
	for _, v := range s.Subscriptions {
		d.URLs[v.ID] = v.URL
	}
	return json.Marshal(d)
}
func DecodeState(b []byte) (State, error) {
	var d diskState
	if e := json.Unmarshal(b, &d); e != nil {
		return State{}, fmt.Errorf("saved state could not be decoded")
	}
	if e := ValidateSettings(d.State.Settings); e != nil {
		return State{}, e
	}
	for i := range d.State.Servers {
		d.State.Servers[i].Outbound = d.Outbounds[d.State.Servers[i].ID]
	}
	for i := range d.State.Subscriptions {
		d.State.Subscriptions[i].URL = d.URLs[d.State.Subscriptions[i].ID]
	}
	return d.State, nil
}
func AtomicWrite(path string, data []byte) error {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".aster-*")
	if e != nil {
		return e
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(data)
	}
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	return replaceFile(tmp, path)
}
