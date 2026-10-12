package osutil

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/aliyun/credagent/pkg/logger"
)

// BinaryInf defines the interface for an executable file.
type BinaryInf interface {
	GetPath() string
	GetPid() int32
	GetSha256() (string, error)
	CheckRisk(cfg *RiskCheckConfig) RiskResult
}

// Binary represents a native executable file in the context of its owning process.
// CheckRisk is stateless — Process holds the per-process risk cache, so caching
// at this level would be dead code (each Binary instance is only checked once
// per Process lifetime via getExe → exe.CheckRisk).
type Binary struct {
	path   string
	pid    int32
	sha256 string
}

// NewBinary creates a BinaryInf for the given exe path + owning PID.
// Delegates to the interpreter factory first to wrap as an Interpreter when applicable.
func NewBinary(exePath string, pid int32) BinaryInf {
	if factory := getInterpreterFactory(); factory != nil {
		if interp := factory(exePath, pid); interp != nil {
			return interp
		}
	}
	return &Binary{path: exePath, pid: pid}
}

// NewBinaryStruct creates a concrete *Binary suitable for embedding in
// other types (e.g. Interpreter). Bypasses the interpreter factory.
func NewBinaryStruct(exePath string, pid int32) *Binary {
	return &Binary{path: exePath, pid: pid}
}

func (b *Binary) GetPath() string { return b.path }
func (b *Binary) GetPid() int32   { return b.pid }

func (b *Binary) GetSha256() (string, error) {
	if b.sha256 != "" {
		return b.sha256, nil
	}
	hash, err := getExeSHA256(b.path)
	if err != nil {
		return "", err
	}
	b.sha256 = hash
	return b.sha256, nil
}

// CheckRisk runs all one-time checks for a native binary:
//  1. exe path trust (system PATH / trusted_programs / blacklist / strict path)
//  2. native env (LD_PRELOAD, etc.)
//
// Stateless — Process.CheckRisk caches the result via p.risk.
// Runtime checks (TracerPid, seccomp, library injection) are handled by
// Process.CheckRisk and run every invocation.
func (b *Binary) CheckRisk(cfg *RiskCheckConfig) RiskResult {
	logger.Debug("[Binary.CheckRisk] pid=%d path=%s", b.pid, b.path)

	if result := b.checkPathTrust(cfg); result.Level == Untrusted {
		logger.Debug("[Binary.CheckRisk] FAIL path-trust pid=%d path=%s reason=%q", b.pid, b.path, result.Reason)
		return result
	}

	if result := b.checkNativeEnv(cfg); result.Level == Untrusted {
		logger.Debug("[Binary.CheckRisk] FAIL native-env pid=%d path=%s reason=%q", b.pid, b.path, result.Reason)
		return result
	}

	logger.Debug("[Binary.CheckRisk] PASS pid=%d path=%s", b.pid, b.path)
	return RiskResult{Level: Trusted}
}

// ReadProcEnviron is the exported wrapper around the platform-specific environ reader.
// Used by the interpreter package to inspect a process's environment.
func ReadProcEnviron(pid int32) ([]string, error) {
	return readProcEnviron(pid)
}

// ReadProcCmdlineArgs returns the command-line arguments of a process as a slice.
// On Linux this reads /proc/<pid>/cmdline (NUL-separated, exact arg boundaries).
func ReadProcCmdlineArgs(pid int32) ([]string, error) {
	return readProcCmdlineArgs(pid)
}

// ReadProcCwd returns the current working directory of a process.
func ReadProcCwd(pid int32) (string, error) {
	return readProcCwd(pid)
}

// CheckScriptPathTrust verifies that a script file path is trustworthy:
//  1. In trustedScripts allowlist → trusted
//  2. In unsafe prefix (/tmp, /home, ...) → untrusted
//  3. File + path chain all root-owned and not group/other writable → trusted
//  4. Otherwise → untrusted
//
// scriptPath is the logical path (namespace-internal) used for policy matching.
// hostPath is the host-accessible path for filesystem checks (e.g. via /proc/<pid>/root).
// If hostPath is empty, scriptPath is used for filesystem checks (non-namespace case).
func CheckScriptPathTrust(scriptPath, hostPath string, trustedScripts []string) RiskResult {
	if hostPath == "" {
		hostPath = scriptPath
	}
	for _, ts := range trustedScripts {
		if ts == scriptPath {
			return RiskResult{Level: Trusted}
		}
	}
	for _, prefix := range unsafePathPrefixes {
		if strings.HasPrefix(scriptPath, prefix) {
			return RiskResult{
				Level:  Untrusted,
				Reason: fmt.Sprintf("[script_trust_check] script in unsafe location: %s", scriptPath),
			}
		}
	}
	if r := checkPathNodeChain(hostPath); r.Level == Untrusted {
		return RiskResult{
			Level:  Untrusted,
			Reason: fmt.Sprintf("[script_trust_check] %s", r.Reason),
		}
	}
	return RiskResult{Level: Trusted}
}

// checkPathTrust verifies the executable's location is trustworthy:
//  1. cfg.BinaryCheck disabled → trusted
//  2. dir in system PATH → trusted
//  3. path in cfg.BinaryCheck.TrustedPrograms → trusted
//  4. path in unsafe prefix (/tmp, /home, ...) → untrusted
//  5. file is root-owned and not group/other writable → trusted
//  6. otherwise → untrusted
func (b *Binary) checkPathTrust(cfg *RiskCheckConfig) RiskResult {
	if cfg != nil && !cfg.BinaryCheck.Enabled {
		logger.Debug("[checkPathTrust] DISABLED pid=%d path=%s", b.pid, b.path)
		return RiskResult{Level: Trusted}
	}

	dir := filepath.Dir(b.path)
	if isInSystemPATH(dir) {
		logger.Debug("[checkPathTrust] PASS via system-PATH pid=%d path=%s", b.pid, b.path)
		return RiskResult{Level: Trusted}
	}

	if cfg != nil && isTrustedProgram(b.path, cfg.BinaryCheck.TrustedPrograms) {
		logger.Debug("[checkPathTrust] PASS via trusted_programs pid=%d path=%s", b.pid, b.path)
		return RiskResult{Level: Trusted}
	}

	for _, prefix := range unsafePathPrefixes {
		if strings.HasPrefix(b.path, prefix) {
			reason := fmt.Sprintf("[binary_check] binary in unsafe location: %s", b.path)
			logger.Warn("%s", reason)
			return RiskResult{Level: Untrusted, Reason: reason}
		}
	}

	// Step 5: check file AND each parent directory — all must be root-owned
	// and not group/other writable. If any ancestor dir is writable, an attacker
	// can replace the binary by removing and recreating intermediate nodes.
	if r := checkPathNodeChain(b.path); r.Level == Untrusted {
		return r
	}

	logger.Debug("[checkPathTrust] PASS via ownership check pid=%d path=%s", b.pid, b.path)
	return RiskResult{Level: Trusted}
}

// checkNativeEnv verifies LD_PRELOAD / LD_LIBRARY_PATH / LD_AUDIT / DYLD_*
// using /proc/<pid>/environ. No-op if cfg disables the check or PID is unknown.
func (b *Binary) checkNativeEnv(cfg *RiskCheckConfig) RiskResult {
	if cfg == nil || !cfg.EnvVarCheck.Enabled || b.pid <= 0 {
		return RiskResult{Level: Trusted}
	}
	envVars, err := readProcEnviron(b.pid)
	if err != nil {
		logger.Debug("checkNativeEnv(%d): cannot read environ: %v", b.pid, err)
		return RiskResult{Level: Trusted}
	}
	return checkNativeEnvRisk(envVars, cfg.EnvVarCheck.TrustedEnv)
}

// checkPathNodeChain verifies that the file at path AND every parent directory
// up to "/" are root-owned (uid=0) and not group/other writable. This prevents
// attacks where an ancestor directory is writable, allowing an attacker to
// remove and replace intermediate path components.
func checkPathNodeChain(path string) RiskResult {
	current := path
	for {
		info, err := os.Lstat(current)
		if err != nil {
			reason := fmt.Sprintf("[binary_check] cannot stat %s (%v)", current, err)
			logger.Warn("%s", reason)
			return RiskResult{Level: Untrusted, Reason: reason}
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			reason := fmt.Sprintf("[binary_check] cannot get ownership info: %s", current)
			logger.Warn("%s", reason)
			return RiskResult{Level: Untrusted, Reason: reason}
		}
		if stat.Uid != 0 {
			reason := fmt.Sprintf("[binary_check] %s not owned by root (uid=%d)", current, stat.Uid)
			logger.Warn("%s", reason)
			return RiskResult{Level: Untrusted, Reason: reason}
		}
		mode := info.Mode()
		if mode&0022 != 0 {
			reason := fmt.Sprintf("[binary_check] %s writable by group/other (mode=%o)", current, mode)
			logger.Warn("%s", reason)
			return RiskResult{Level: Untrusted, Reason: reason}
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	return RiskResult{Level: Trusted}
}

// unsafePathPrefixes lists directory prefixes where binaries should never be trusted.
var unsafePathPrefixes = []string{
	"/tmp/",
	"/var/tmp/",
	"/dev/shm/",
	"/home/",
	"/run/user/",
}

// --- System PATH management ---

var systemPATHDirs []string

// SetSystemPATH stores the system PATH directories at daemon startup.
// Should be called once during credagent initialization with os.Getenv("PATH").
func SetSystemPATH(pathEnv string) {
	systemPATHDirs = filepath.SplitList(pathEnv)
}

func isInSystemPATH(dir string) bool {
	for _, d := range systemPATHDirs {
		if d == dir {
			return true
		}
	}
	return false
}

// IsInSystemPATH exposes the PATH membership check for sub-packages (e.g.
// interpreter, which uses PATH as the source of truth for "valid interpreter
// location" instead of a hardcoded directory list).
func IsInSystemPATH(dir string) bool {
	return isInSystemPATH(dir)
}


func isTrustedProgram(path string, trusted []string) bool {
	for _, t := range trusted {
		if t == path {
			return true
		}
	}
	return false
}

// InterpreterFactory is a function that attempts to create an interpreter BinaryInf.
// Returns nil if the path is not a recognized interpreter.
type InterpreterFactory func(exePath string, pid int32) BinaryInf

var globalInterpreterFactory InterpreterFactory

// SetInterpreterFactory registers the interpreter factory.
// Called by the interpreter package at init time.
func SetInterpreterFactory(f InterpreterFactory) {
	globalInterpreterFactory = f
}

func getInterpreterFactory() InterpreterFactory {
	return globalInterpreterFactory
}
