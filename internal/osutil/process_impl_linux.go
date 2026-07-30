//go:build linux

package osutil

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Mockable I/O hooks — tests can replace these to inject fake /proc data.
var (
	procStatusReader  = defaultProcStatusReader
	procMapsReader    = defaultProcMapsReader
	procEnvironReader = defaultProcEnvironReader
	procExeReader     = defaultProcExeReader
)

func defaultProcStatusReader(pid int32) (string, error) {
	statusPath := filepath.Join("/proc", strconv.Itoa(int(pid)), "status")
	data, err := os.ReadFile(statusPath)
	return string(data), err
}

func defaultProcMapsReader(pid int32) ([]byte, error) {
	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	return os.ReadFile(mapsPath)
}

func defaultProcEnvironReader(pid int32) ([]string, error) {
	environPath := filepath.Join("/proc", strconv.Itoa(int(pid)), "environ")
	data, err := os.ReadFile(environPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", environPath, err)
	}
	return strings.Split(string(data), "\x00"), nil
}

func defaultProcExeReader(pid int32) (string, error) {
	link := filepath.Join("/proc", strconv.Itoa(int(pid)), "exe")
	path, err := os.Readlink(link)
	if err != nil {
		return "", fmt.Errorf("readlink %s: %w", link, err)
	}
	return path, nil
}

// NewProcess creates a new Process for the given PID on Linux.
func NewProcess(pid int32) ProcessInf {
	p := &Process{pid: pid}

	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	content, err := os.ReadFile(statPath)
	if err != nil {
		panic(fmt.Sprintf("NewProcess(%d): %v", pid, err))
	}
	fields := strings.Fields(string(content))
	if len(fields) < 22 {
		panic(fmt.Sprintf("NewProcess(%d): not enough fields in stat", pid))
	}
	ticks, err := strconv.ParseUint(fields[21], 10, 64)
	if err != nil {
		panic(fmt.Sprintf("NewProcess(%d): parse starttime: %v", pid, err))
	}
	bootTime, err := getSystemBootTime()
	if err != nil {
		panic(fmt.Sprintf("NewProcess(%d): boot time: %v", pid, err))
	}
	p.startTime = bootTime + uint64(float64(ticks)/100.0)

	return p
}

func (p *Process) procDir() string {
	return filepath.Join("/proc", strconv.Itoa(int(p.pid)))
}

func (p *Process) platformGetExePath() (string, error) {
	return procExeReader(p.pid)
}

func (p *Process) platformGetPpid() (int32, error) {
	data, err := os.ReadFile(filepath.Join(p.procDir(), "status"))
	if err != nil {
		return 0, err
	}
	return parseStatusField(string(data), "PPid:")
}

func (p *Process) platformGetUid() (int32, error) {
	data, err := os.ReadFile(filepath.Join(p.procDir(), "status"))
	if err != nil {
		return 0, err
	}
	return parseStatusField(string(data), "Uid:")
}

func (p *Process) platformGetGid() (int32, error) {
	data, err := os.ReadFile(filepath.Join(p.procDir(), "status"))
	if err != nil {
		return 0, err
	}
	return parseStatusField(string(data), "Gid:")
}

func (p *Process) platformReadEnviron() ([]string, error) {
	return readProcEnviron(p.pid)
}

// readProcEnviron reads /proc/<pid>/environ and splits on NUL.
// Used by both Process and Binary (the latter from a non-method context).
func readProcEnviron(pid int32) ([]string, error) {
	return procEnvironReader(pid)
}

func (p *Process) platformReadCmdline() (string, error) {
	cmdlinePath := filepath.Join(p.procDir(), "cmdline")
	data, err := os.ReadFile(cmdlinePath)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", cmdlinePath, err)
	}
	return strings.ReplaceAll(strings.TrimRight(string(data), "\x00"), "\x00", " "), nil
}

func readProcCwd(pid int32) (string, error) {
	link := filepath.Join("/proc", strconv.Itoa(int(pid)), "cwd")
	path, err := os.Readlink(link)
	if err != nil {
		return "", fmt.Errorf("readlink %s: %w", link, err)
	}
	return path, nil
}

// ProcRootPath returns the host-accessible path for file I/O on a namespace-internal
// path. Uses /proc/<pid>/root which is a kernel magic link that traverses the
// target process's mount namespace.
func ProcRootPath(pid int32, namespacePath string) string {
	return fmt.Sprintf("/proc/%d/root%s", pid, namespacePath)
}

// ResolveNamespacePath translates a namespace-internal absolute path to the
// corresponding host path by parsing /proc/<pid>/mountinfo. This is needed for
// policy matching: the user configures trusted paths using host paths, but the
// process sees namespace-remapped paths.
//
// Returns the original namespacePath unchanged if translation fails or no
// mount mapping covers the path.
func ResolveNamespacePath(pid int32, namespacePath string) string {
	mountinfoPath := fmt.Sprintf("/proc/%d/mountinfo", pid)
	data, err := os.ReadFile(mountinfoPath)
	if err != nil {
		return namespacePath
	}

	var bestMount string
	var bestRoot string
	bestLen := 0

	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		// fields[3] = root (path within the filesystem)
		// fields[4] = mount point (where it appears in the namespace)
		root := fields[3]
		mountPoint := fields[4]

		// Find the longest mount point that is a prefix of namespacePath
		if mountPoint == namespacePath || (strings.HasPrefix(namespacePath, mountPoint) &&
			(mountPoint == "/" || namespacePath[len(mountPoint)] == '/')) {
			if len(mountPoint) > bestLen {
				bestLen = len(mountPoint)
				bestMount = mountPoint
				bestRoot = root
			}
		}
	}

	if bestLen == 0 || bestRoot == "" {
		return namespacePath
	}

	// Strip the mount point prefix from namespacePath, append remainder to root
	var remainder string
	if bestMount == "/" {
		remainder = namespacePath
	} else {
		remainder = namespacePath[len(bestMount):]
	}
	hostPath := filepath.Join(bestRoot, remainder)
	return filepath.Clean(hostPath)
}

func readProcCmdlineArgs(pid int32) ([]string, error) {
	cmdlinePath := filepath.Join("/proc", strconv.Itoa(int(pid)), "cmdline")
	data, err := os.ReadFile(cmdlinePath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", cmdlinePath, err)
	}
	trimmed := strings.TrimRight(string(data), "\x00")
	if trimmed == "" {
		return nil, nil
	}
	return strings.Split(trimmed, "\x00"), nil
}

func (p *Process) platformCheckRuntime(cfg *RiskCheckConfig) RiskResult {
	if cfg == nil {
		cfg = DefaultRiskCheckConfig()
	}

	// 1. Process status check (TracerPid + Seccomp)
	if cfg.ProcessStatusCheck.Enabled {
		content, err := procStatusReader(p.pid)
		if err != nil {
			return RiskResult{
				Level:  Untrusted,
				Reason: fmt.Sprintf("[process_status_check] cannot read status for PID %d: %v", p.pid, err),
			}
		}

		var tracerPid int64
		var seccompMode int
		for _, line := range strings.Split(content, "\n") {
			if strings.HasPrefix(line, "TracerPid:") {
				parts := strings.Fields(line)
				if len(parts) > 1 {
					tracerPid, _ = strconv.ParseInt(parts[1], 10, 64)
				}
			} else if strings.HasPrefix(line, "Seccomp:") {
				parts := strings.Fields(line)
				if len(parts) > 1 {
					seccompMode, _ = strconv.Atoi(parts[1])
				}
			}
		}

		if tracerPid != 0 {
			return RiskResult{
				Level:  Untrusted,
				Reason: fmt.Sprintf("[process_status_check] process is being traced (tracer PID: %d)", tracerPid),
			}
		}
		if seccompMode == 2 {
			return RiskResult{
				Level:  Untrusted,
				Reason: fmt.Sprintf("[process_status_check] seccomp filter installed (mode=%d), possible syscall interception", seccompMode),
			}
		}
	}

	return RiskResult{Level: Trusted}
}

func (p *Process) platformCheckLibraryInjection(cfg *RiskCheckConfig) RiskResult {
	if cfg == nil || !cfg.LibraryInjectionCheck.Enabled {
		return RiskResult{Level: Trusted}
	}
	return checkLibraryInjectionLinux(p.pid, cfg.LibraryInjectionCheck.TrustedLibPaths)
}

func parseStatusField(content, prefix string) (int32, error) {
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(line, prefix) {
			parts := strings.Fields(line)
			if len(parts) > 1 {
				val, err := strconv.ParseInt(parts[1], 10, 32)
				if err != nil {
					return 0, fmt.Errorf("parse %s: %w", prefix, err)
				}
				return int32(val), nil
			}
		}
	}
	return 0, fmt.Errorf("%s not found in status", prefix)
}

// checkLibraryInjectionLinux checks /proc/<pid>/maps for suspicious .so files.
func checkLibraryInjectionLinux(pid int32, trustedLibPaths []string) RiskResult {
	mapsBytes, err := procMapsReader(pid)
	if err != nil {
		return RiskResult{Level: Trusted}
	}

	suspiciousPrefixes := []string{"/tmp/", "/dev/shm/", "/var/tmp/", "/home/"}

	for _, line := range strings.Split(string(mapsBytes), "\n") {
		if !strings.Contains(line, ".so") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		libPath := fields[len(fields)-1]
		for _, prefix := range suspiciousPrefixes {
			if strings.HasPrefix(libPath, prefix) {
				if isTrustedProgram(libPath, trustedLibPaths) {
					continue
				}
				return RiskResult{
					Level:  Untrusted,
					Reason: "[library_injection_check] suspicious library from non-standard path: " + libPath,
				}
			}
		}
	}
	return RiskResult{Level: Trusted}
}
