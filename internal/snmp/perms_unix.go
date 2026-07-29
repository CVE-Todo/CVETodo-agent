//go:build !windows

package snmp

import (
	"fmt"
	"os"
)

// checkHostsFilePerms refuses a hosts file readable by group or other: it
// contains device credentials. Mirrors the 0600 discipline of the agent's
// YAML config.
func checkHostsFilePerms(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return fmt.Errorf("%s is readable by other users (mode %04o); it contains SNMP credentials — run: chmod 600 %s", path, mode, path)
	}
	return nil
}
