package platform

import (
	"fmt"
	"os/exec"
	"syscall"
)

// The caller supplies a path already authenticated by the update verifier.
func LaunchInstaller(path string) error {
	cmd := exec.Command(path, "/S", "/UPDATE")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x00000008 | 0x00000200}
	if e := cmd.Start(); e != nil {
		return fmt.Errorf("could not start the verified installer")
	}
	return cmd.Process.Release()
}
