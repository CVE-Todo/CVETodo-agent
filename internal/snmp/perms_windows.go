//go:build windows

package snmp

import "os"

// checkHostsFilePerms only verifies the file exists on Windows; POSIX
// permission bits are meaningless there and ACL inspection is not worth the
// complexity for v1.
func checkHostsFilePerms(path string) error {
	_, err := os.Stat(path)
	return err
}
