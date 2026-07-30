package osutil

import "fmt"

// MockProcess is a platform-independent ProcessInf implementation for testing.
type MockProcess struct {
	pid        int32
	startTime  uint64
	uid        int32
	gid        int32
	exePath    string
	sha256     string
	cmdline    string
	permitUuid string
	envVars    map[string]string
}

func NewMockProcess(pid int32, opts ...TestProcessOption) *MockProcess {
	cfg := &testProcessConfig{}
	for _, opt := range opts {
		opt(cfg)
	}
	m := &MockProcess{pid: pid, envVars: make(map[string]string)}
	if cfg.stSet {
		m.startTime = cfg.startTime
	}
	if cfg.uidSet {
		m.uid = cfg.uid
	}
	if cfg.gidSet {
		m.gid = cfg.gid
	}
	if cfg.exeSet {
		m.exePath = cfg.exePath
	}
	if cfg.sha256Set {
		m.sha256 = cfg.sha256
	}
	if cfg.cmdSet {
		m.cmdline = cfg.cmdline
	}
	if cfg.uuidSet {
		m.permitUuid = cfg.permitUuid
		m.envVars["CRED_PERMIT_UUID"] = cfg.permitUuid
	}
	return m
}

func (m *MockProcess) GetPid() int32       { return m.pid }
func (m *MockProcess) GetStartTime() uint64 { return m.startTime }
func (m *MockProcess) GetUid() int32       { return m.uid }
func (m *MockProcess) GetGid() int32       { return m.gid }
func (m *MockProcess) GetParent() ProcessInf { return nil }

func (m *MockProcess) GetCmdline() string {
	if m.cmdline != "" {
		return m.cmdline
	}
	return m.exePath
}

func (m *MockProcess) GetEnvVar(name string) string {
	return m.envVars[name]
}

func (m *MockProcess) GetSha256() (string, error) {
	if m.sha256 != "" {
		return m.sha256, nil
	}
	if m.exePath != "" {
		return getExeSHA256(m.exePath)
	}
	return "", fmt.Errorf("no sha256 available for mock process %d", m.pid)
}

func (m *MockProcess) CheckRisk(_ *RiskCheckConfig) RiskResult {
	return RiskResult{Level: Trusted}
}

func (m *MockProcess) IsSame(other ProcessInf) bool {
	return m.pid == other.GetPid() && m.startTime == other.GetStartTime()
}

// SetEnvVar sets an environment variable on the mock (for testing).
func (m *MockProcess) SetEnvVar(name, value string) {
	m.envVars[name] = value
}

// GetExePath returns the exe path (for compatibility with code that needs path for display).
func (m *MockProcess) GetExePath() string {
	return m.exePath
}
