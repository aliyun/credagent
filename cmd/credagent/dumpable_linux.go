//go:build linux

package main

import "golang.org/x/sys/unix"

// setNonDumpable marks the process as non-dumpable (Linux: PR_SET_DUMPABLE=0)
// to prevent the master key from leaking via crash dumps or /proc/<pid>/mem.
func setNonDumpable() error {
	return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}
