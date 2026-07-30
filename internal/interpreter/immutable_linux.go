package interpreter

import (
	"os"
	"syscall"
	"unsafe"
)

// isImmutable checks the FS_IMMUTABLE_FL attribute via ioctl.
func isImmutable(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	var flags int32
	// FS_IOC_GETFLAGS = 0x80086601 on linux/amd64
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), 0x80086601, uintptr(unsafe.Pointer(&flags)))
	if errno != 0 {
		return false
	}
	// FS_IMMUTABLE_FL = 0x00000010
	return (flags & 0x10) != 0
}
