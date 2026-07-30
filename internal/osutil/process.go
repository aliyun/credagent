package osutil

import (
	"fmt"
	"strings"

	"github.com/alibaba/CredAgent/pkg/logger"
)

// ProcessInf defines the core interface for process identity and risk assessment.
type ProcessInf interface {
	GetPid() int32
	GetStartTime() uint64
	GetUid() int32
	GetGid() int32
	GetParent() ProcessInf
	GetCmdline() string
	GetEnvVar(name string) string
	GetSha256() (string, error)
	CheckRisk(cfg *RiskCheckConfig) RiskResult
	IsSame(other ProcessInf) bool
}

// CmdlineLookupFunc returns the original execve cmdline for a given PID.
// Kept as a type alias for backward compatibility during migration.
type CmdlineLookupFunc func(pid uint32) (string, bool)

// ProcessProvider supplies cached ProcessInf instances by PID. The cache
// package registers an implementation so GetParent can reuse a single
// instance for a given (pid, startTime), letting the risk-check cache on
// long-living ancestors (e.g. login bash) be shared across FUSE callers.
type ProcessProvider interface {
	GetOrTouchProcess(pid uint32) ProcessInf
}

var globalProcessProvider ProcessProvider

// SetProcessProvider registers a global ProcessProvider. If unset, GetParent
// falls back to NewProcess (uncached).
func SetProcessProvider(p ProcessProvider) {
	globalProcessProvider = p
}

// Process is the core process struct. Platform-specific methods are defined
// in process_impl_linux.go / process_impl_darwin.go via build tags.
type Process struct {
	pid       int32
	startTime uint64

	// Lazily-loaded fields
	exe    BinaryInf
	parent ProcessInf

	// Cached risk state
	risk       RiskLevel
	riskReason string

	// ancestorVerified: the full ancestor chain has already been verified.
	// Allows Phase 3 to short-circuit when the process has already passed
	// a complete CheckRisk. Set only when risk == Trusted AND Phase 3 completed.
	ancestorVerified bool

	parentLoaded bool
}

func (p *Process) GetPid() int32       { return p.pid }
func (p *Process) GetStartTime() uint64 { return p.startTime }
func (p *Process) IsHarnessed() bool    { return p.risk == FreeCheck }

func (p *Process) GetUid() int32 {
	uid, err := p.platformGetUid()
	if err != nil {
		panic(fmt.Sprintf("GetUid(%d): %v", p.pid, err))
	}
	return uid
}

func (p *Process) GetGid() int32 {
	gid, err := p.platformGetGid()
	if err != nil {
		panic(fmt.Sprintf("GetGid(%d): %v", p.pid, err))
	}
	return gid
}

func (p *Process) GetParent() ProcessInf {
	if p.parentLoaded {
		return p.parent
	}
	p.parentLoaded = true

	ppid, err := p.platformGetPpid()
	if err != nil {
		logger.Debug("GetParent(%d): %v", p.pid, err)
		return nil
	}
	if ppid <= 1 {
		return nil
	}
	if provider := globalProcessProvider; provider != nil {
		p.parent = provider.GetOrTouchProcess(uint32(ppid))
		logger.Debug("[Process.GetParent] pid=%d ppid=%d via cache provider", p.pid, ppid)
	} else {
		p.parent = NewProcess(ppid)
		logger.Debug("[Process.GetParent] pid=%d ppid=%d fresh (no provider)", p.pid, ppid)
	}
	return p.parent
}

func (p *Process) GetCmdline() string {
	if provider := GetCmdlineProvider(); provider != nil {
		if cmd, ok := provider.Lookup(uint32(p.pid)); ok {
			return cmd
		}
	}
	cmd, err := p.platformReadCmdline()
	if err != nil {
		panic(fmt.Sprintf("GetCmdline(%d): %v", p.pid, err))
	}
	return cmd
}

func (p *Process) GetEnvVar(name string) string {
	envVars, err := p.platformReadEnviron()
	if err != nil {
		return ""
	}
	prefix := name + "="
	for _, envVar := range envVars {
		if strings.HasPrefix(envVar, prefix) {
			return envVar[len(prefix):]
		}
	}
	return ""
}

func (p *Process) GetSha256() (string, error) {
	exe, err := p.getExe()
	if err != nil {
		return "", err
	}
	return exe.GetSha256()
}

func (p *Process) IsSame(other ProcessInf) bool {
	return p.pid == other.GetPid() && p.startTime == other.GetStartTime()
}

func (p *Process) getExe() (BinaryInf, error) {
	if p.exe != nil {
		return p.exe, nil
	}
	exePath, err := p.platformGetExePath()
	if err != nil {
		return nil, fmt.Errorf("getExe(%d): %w", p.pid, err)
	}
	p.exe = NewBinary(exePath, p.pid)
	return p.exe, nil
}

// GetExePath returns the executable path (for logging/display purposes).
func (p *Process) GetExePath() string {
	exePath, err := p.platformGetExePath()
	if err != nil {
		return fmt.Sprintf("<pid:%d>", p.pid)
	}
	return exePath
}


// --- Test helpers ---

type testProcessConfig struct {
	uid        int32
	gid        int32
	ppid       int32
	exePath    string
	sha256     string
	cmdline    string
	permitUuid string
	startTime  uint64
	uidSet     bool
	gidSet     bool
	ppidSet    bool
	exeSet     bool
	sha256Set  bool
	cmdSet     bool
	uuidSet    bool
	stSet      bool
}

type TestProcessOption func(*testProcessConfig)

func WithUid(uid int32) TestProcessOption {
	return func(c *testProcessConfig) { c.uid = uid; c.uidSet = true }
}

func WithGid(gid int32) TestProcessOption {
	return func(c *testProcessConfig) { c.gid = gid; c.gidSet = true }
}

func WithExePath(path string) TestProcessOption {
	return func(c *testProcessConfig) { c.exePath = path; c.exeSet = true }
}

func WithSha256(sha string) TestProcessOption {
	return func(c *testProcessConfig) { c.sha256 = sha; c.sha256Set = true }
}

func WithCmdline(cmd string) TestProcessOption {
	return func(c *testProcessConfig) { c.cmdline = cmd; c.cmdSet = true }
}

func WithPermitUuid(uuid string) TestProcessOption {
	return func(c *testProcessConfig) { c.permitUuid = uuid; c.uuidSet = true }
}

func WithStartTime(st uint64) TestProcessOption {
	return func(c *testProcessConfig) { c.startTime = st; c.stSet = true }
}

func WithPpid(ppid int32) TestProcessOption {
	return func(c *testProcessConfig) { c.ppid = ppid; c.ppidSet = true }
}
