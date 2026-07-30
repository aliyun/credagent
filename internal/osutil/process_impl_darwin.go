//go:build darwin

package osutil

/*
#include <libproc.h>
#include <sys/sysctl.h>
#include <sys/proc_info.h>
*/
import "C"

import (
	"fmt"
	"strings"
	"unsafe"
)

// NewProcess creates a new Process for the given PID on macOS.
func NewProcess(pid int32) ProcessInf {
	p := &Process{pid: pid}

	st, err := getProcessStartTimeDarwin(uint32(pid))
	if err != nil {
		panic(fmt.Sprintf("NewProcess(%d): %v", pid, err))
	}
	p.startTime = st

	return p
}

func (p *Process) platformGetExePath() (string, error) {
	return getProcPidPath(p.pid)
}

func (p *Process) platformGetPpid() (int32, error) {
	info, err := getKinfoProc(p.pid)
	if err != nil {
		return 0, err
	}
	return int32(info.kp_eproc.e_ppid), nil
}

func (p *Process) platformGetUid() (int32, error) {
	info, err := getKinfoProc(p.pid)
	if err != nil {
		return 0, err
	}
	return int32(info.kp_eproc.e_ucred.cr_uid), nil
}

func (p *Process) platformGetGid() (int32, error) {
	info, err := getKinfoProc(p.pid)
	if err != nil {
		return 0, err
	}
	return int32(info.kp_eproc.e_ucred.cr_groups[0]), nil
}

func (p *Process) platformReadEnviron() ([]string, error) {
	return readProcEnviron(p.pid)
}

// readProcEnviron returns the environ variables for the given PID via sysctl.
func readProcEnviron(pid int32) ([]string, error) {
	vars := getEnvironFromSysctl(pid)
	if vars == nil {
		return nil, fmt.Errorf("failed to read environ for pid %d", pid)
	}
	return vars, nil
}

func (p *Process) platformReadCmdline() (string, error) {
	return getCmdlineFromSysctl(p.pid)
}

func (p *Process) platformCheckRuntime(cfg *RiskCheckConfig) RiskResult {
	if cfg == nil {
		cfg = DefaultRiskCheckConfig()
	}

	if cfg.ProcessStatusCheck.Enabled {
		tracerPid, err := getTracerPidDarwin(p.pid)
		if err != nil {
			return RiskResult{
				Level:  Untrusted,
				Reason: fmt.Sprintf("[process_status_check] cannot verify tracing status (PID: %d): %v", p.pid, err),
			}
		}
		if tracerPid != 0 {
			return RiskResult{
				Level:  Untrusted,
				Reason: fmt.Sprintf("[process_status_check] process is being traced (PID: %d)", p.pid),
			}
		}
	}

	return RiskResult{Level: Trusted}
}

func (p *Process) platformCheckLibraryInjection(cfg *RiskCheckConfig) RiskResult {
	return RiskResult{Level: Trusted}
}

func getTracerPidDarwin(pid int32) (int32, error) {
	info, err := getKinfoProc(pid)
	if err != nil {
		return 0, err
	}
	if info.kp_proc.p_flag&0x00000800 != 0 {
		return 1, nil
	}
	return 0, nil
}

func getProcessStartTimeDarwin(pid uint32) (uint64, error) {
	var pbi C.struct_proc_bsdinfo
	ret := C.proc_pidinfo(C.int(pid), C.PROC_PIDTBSDINFO, 0,
		unsafe.Pointer(&pbi), C.int(unsafe.Sizeof(pbi)))
	if ret <= 0 {
		return 0, fmt.Errorf("proc_pidinfo PROC_PIDTBSDINFO failed for pid %d", pid)
	}
	return uint64(pbi.pbi_start_tvsec), nil
}

// --- macOS platform functions ---

func getProcPidPath(pid int32) (string, error) {
	buf := make([]byte, C.PROC_PIDPATHINFO_MAXSIZE)
	ret := C.proc_pidpath(C.int(pid), unsafe.Pointer(&buf[0]), C.uint32_t(len(buf)))
	if ret <= 0 {
		return "", fmt.Errorf("proc_pidpath failed for pid %d", pid)
	}
	n := 0
	for n < len(buf) && buf[n] != 0 {
		n++
	}
	return string(buf[:n]), nil
}

func getKinfoProc(pid int32) (C.struct_kinfo_proc, error) {
	var info C.struct_kinfo_proc
	var mib [4]C.int
	mib[0] = C.CTL_KERN
	mib[1] = C.KERN_PROC
	mib[2] = C.KERN_PROC_PID
	mib[3] = C.int(pid)
	size := C.size_t(unsafe.Sizeof(info))
	ret := C.sysctl(&mib[0], 4, unsafe.Pointer(&info), &size, nil, 0)
	if ret != 0 {
		return info, fmt.Errorf("sysctl KERN_PROC_PID failed for pid %d", pid)
	}
	return info, nil
}

func getCmdlineFromSysctl(pid int32) (string, error) {
	var argmax C.int
	var mib [2]C.int
	mib[0] = C.CTL_KERN
	mib[1] = C.KERN_ARGMAX
	size := C.size_t(unsafe.Sizeof(argmax))
	C.sysctl(&mib[0], 2, unsafe.Pointer(&argmax), &size, nil, 0)

	buf := make([]byte, int(argmax))
	var mib2 [3]C.int
	mib2[0] = C.CTL_KERN
	mib2[1] = C.KERN_PROCARGS2
	mib2[2] = C.int(pid)
	bufSize := C.size_t(len(buf))

	ret := C.sysctl(&mib2[0], 3, unsafe.Pointer(&buf[0]), &bufSize, nil, 0)
	if ret != 0 {
		return "", fmt.Errorf("sysctl KERN_PROCARGS2 failed for pid %d", pid)
	}
	buf = buf[:bufSize]

	if len(buf) < 4 {
		return "", fmt.Errorf("KERN_PROCARGS2 buffer too small for pid %d", pid)
	}

	argc := *(*int32)(unsafe.Pointer(&buf[0]))

	pos := 4
	for pos < len(buf) && buf[pos] != 0 {
		pos++
	}
	for pos < len(buf) && buf[pos] == 0 {
		pos++
	}

	var args []string
	count := int32(0)
	for pos < len(buf) && count < argc {
		end := pos
		for end < len(buf) && buf[end] != 0 {
			end++
		}
		if end > pos {
			args = append(args, string(buf[pos:end]))
			count++
		}
		pos = end + 1
	}

	return strings.Join(args, " "), nil
}

func readProcCwd(pid int32) (string, error) {
	// macOS doesn't have /proc/pid/cwd; use proc_pidinfo with PROC_PIDVNODEPATHINFO
	var pathInfo C.struct_proc_vnodepathinfo
	ret := C.proc_pidinfo(C.int(pid), C.PROC_PIDVNODEPATHINFO, 0,
		unsafe.Pointer(&pathInfo), C.int(unsafe.Sizeof(pathInfo)))
	if ret <= 0 {
		return "", fmt.Errorf("proc_pidinfo PROC_PIDVNODEPATHINFO failed for pid %d", pid)
	}
	cwd := C.GoString(&pathInfo.pvi_cdir.vip_path[0])
	return cwd, nil
}

// ProcRootPath on macOS returns the path unchanged — macOS has no mount
// namespaces, so namespace path translation is not needed.
func ProcRootPath(pid int32, namespacePath string) string {
	return namespacePath
}

// ResolveNamespacePath on macOS returns the path unchanged.
func ResolveNamespacePath(pid int32, namespacePath string) string {
	return namespacePath
}

func readProcCmdlineArgs(pid int32) ([]string, error) {
	cmd, err := getCmdlineFromSysctl(pid)
	if err != nil {
		return nil, err
	}
	if cmd == "" {
		return nil, nil
	}
	return strings.Split(cmd, " "), nil
}

func getEnvironFromSysctl(pid int32) []string {
	var argmax C.int
	var mib [2]C.int
	mib[0] = C.CTL_KERN
	mib[1] = C.KERN_ARGMAX
	size := C.size_t(unsafe.Sizeof(argmax))
	C.sysctl(&mib[0], 2, unsafe.Pointer(&argmax), &size, nil, 0)

	buf := make([]byte, int(argmax))
	var mib2 [3]C.int
	mib2[0] = C.CTL_KERN
	mib2[1] = C.KERN_PROCARGS2
	mib2[2] = C.int(pid)
	bufSize := C.size_t(len(buf))

	ret := C.sysctl(&mib2[0], 3, unsafe.Pointer(&buf[0]), &bufSize, nil, 0)
	if ret != 0 {
		return nil
	}
	buf = buf[:bufSize]

	if len(buf) < 4 {
		return nil
	}

	argc := *(*int32)(unsafe.Pointer(&buf[0]))

	pos := 4
	for pos < len(buf) && buf[pos] != 0 {
		pos++
	}
	for pos < len(buf) && buf[pos] == 0 {
		pos++
	}

	count := int32(0)
	for pos < len(buf) && count < argc {
		for pos < len(buf) && buf[pos] != 0 {
			pos++
		}
		count++
		pos++
	}

	for pos < len(buf) && buf[pos] == 0 {
		pos++
	}

	var envVars []string
	for pos < len(buf) {
		end := pos
		for end < len(buf) && buf[end] != 0 {
			end++
		}
		if end <= pos {
			break
		}
		envVars = append(envVars, string(buf[pos:end]))
		pos = end + 1
	}
	return envVars
}
