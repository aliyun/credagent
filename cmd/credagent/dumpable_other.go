//go:build !linux

package main

// setNonDumpable is a no-op on non-Linux (e.g. macOS); core dumps are already
// disabled via syscall.Setrlimit(RLIMIT_CORE, 0) in the caller.
func setNonDumpable() error { return nil }
