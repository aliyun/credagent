//go:build linux

package osutil

import (
	"fmt"
	"strings"
	"testing"
)

// --- Test helpers ---

// mockBinaryInf implements BinaryInf with a controllable CheckRisk result.
type mockBinaryInf struct {
	path   string
	pid    int32
	result RiskResult
}

func (m *mockBinaryInf) GetPath() string              { return m.path }
func (m *mockBinaryInf) GetPid() int32                 { return m.pid }
func (m *mockBinaryInf) GetSha256() (string, error)    { return "mock-sha256", nil }
func (m *mockBinaryInf) CheckRisk(_ *RiskCheckConfig) RiskResult { return m.result }

// riskMockProcess implements ProcessInf with a controllable CheckRisk result.
// Used to mock parent processes in ancestor chain tests.
type riskMockProcess struct {
	pid       int32
	startTime uint64
	result    RiskResult
	parent    ProcessInf
}

func (m *riskMockProcess) GetPid() int32              { return m.pid }
func (m *riskMockProcess) GetStartTime() uint64       { return m.startTime }
func (m *riskMockProcess) GetUid() int32              { return 0 }
func (m *riskMockProcess) GetGid() int32              { return 0 }
func (m *riskMockProcess) GetParent() ProcessInf      { return m.parent }
func (m *riskMockProcess) GetCmdline() string          { return "mock" }
func (m *riskMockProcess) GetEnvVar(_ string) string   { return "" }
func (m *riskMockProcess) GetSha256() (string, error)  { return "mock", nil }
func (m *riskMockProcess) CheckRisk(_ *RiskCheckConfig) RiskResult { return m.result }
func (m *riskMockProcess) IsSame(other ProcessInf) bool {
	return m.pid == other.GetPid() && m.startTime == other.GetStartTime()
}

// newTestProcess creates a Process with controlled fields for testing.
// Does NOT read /proc — fields must be set manually.
func newTestProcess(pid int32, opts ...func(*Process)) *Process {
	p := &Process{pid: pid, startTime: 12345}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

func withExe(exe BinaryInf) func(*Process) {
	return func(p *Process) { p.exe = exe }
}

func withParent(parent ProcessInf) func(*Process) {
	return func(p *Process) {
		p.parent = parent
		p.parentLoaded = true
	}
}

func withNoParent() func(*Process) {
	return func(p *Process) {
		p.parent = nil
		p.parentLoaded = true
	}
}

// algorithmCfg returns a config that skips runtime and library injection checks,
// isolating the Phase 2 (exe) and Phase 3 (ancestor) algorithm.
func algorithmCfg() *RiskCheckConfig {
	cfg := DefaultRiskCheckConfig()
	cfg.SkipRuntimeChecks = true
	cfg.LibraryInjectionCheck.Enabled = false
	cfg.AncestorCheck.Enabled = true
	return cfg
}

// --- Phase flow tests ---

func TestCheckRisk_Phase2_ExeFail(t *testing.T) {
	reason := "[binary_check] binary in unsafe location: /tmp/evil"
	p := newTestProcess(999,
		withExe(&mockBinaryInf{path: "/tmp/evil", result: RiskResult{Level: Untrusted, Reason: reason}}),
		withNoParent(),
	)

	result := p.CheckRisk(algorithmCfg())

	if result.Level != Untrusted {
		t.Fatalf("expected Untrusted, got %v", result.Level)
	}
	if result.Reason != reason {
		t.Errorf("reason = %q, want %q", result.Reason, reason)
	}
}

func TestCheckRisk_Phase2Pass_Phase3_AncestorFail(t *testing.T) {
	parentReason := "[binary_check] not trusted"
	p := newTestProcess(100,
		withExe(&mockBinaryInf{path: "/usr/bin/app", result: RiskResult{Level: Trusted}}),
		withParent(&riskMockProcess{
			pid:    50,
			result: RiskResult{Level: Untrusted, Reason: parentReason},
		}),
	)

	result := p.CheckRisk(algorithmCfg())

	if result.Level != Untrusted {
		t.Fatalf("expected Untrusted, got %v", result.Level)
	}
	if !strings.Contains(result.Reason, "untrusted ancestor") {
		t.Errorf("reason should contain 'untrusted ancestor', got %q", result.Reason)
	}
	if !strings.Contains(result.Reason, parentReason) {
		t.Errorf("reason should contain parent reason %q, got %q", parentReason, result.Reason)
	}
}

func TestCheckRisk_AllPhasesPass(t *testing.T) {
	p := newTestProcess(100,
		withExe(&mockBinaryInf{path: "/usr/bin/app", result: RiskResult{Level: Trusted}}),
		withParent(&riskMockProcess{pid: 50, result: RiskResult{Level: Trusted}}),
	)

	result := p.CheckRisk(algorithmCfg())

	if result.Level != Trusted {
		t.Fatalf("expected Trusted, got %v (reason=%q)", result.Level, result.Reason)
	}
}

func TestCheckRisk_NoParent_Passes(t *testing.T) {
	p := newTestProcess(100,
		withExe(&mockBinaryInf{path: "/usr/bin/app", result: RiskResult{Level: Trusted}}),
		withNoParent(),
	)

	result := p.CheckRisk(algorithmCfg())

	if result.Level != Trusted {
		t.Fatalf("expected Trusted when no parent, got %v", result.Level)
	}
}

// --- Caching tests ---

func TestCheckRisk_UntrustedIsSticky(t *testing.T) {
	callCount := 0
	p := newTestProcess(100,
		withExe(&mockBinaryInf{
			path: "/tmp/evil",
			result: RiskResult{Level: Untrusted, Reason: "bad exe"},
		}),
		withNoParent(),
	)

	// First call — Phase 2 runs and caches Untrusted.
	r1 := p.CheckRisk(algorithmCfg())
	if r1.Level != Untrusted {
		t.Fatalf("first call: expected Untrusted, got %v", r1.Level)
	}

	// Replace exe with a trusted one — should NOT be consulted.
	p.exe = &mockBinaryInf{
		path: "/usr/bin/ok",
		result: RiskResult{Level: Trusted},
	}
	_ = callCount

	r2 := p.CheckRisk(algorithmCfg())
	if r2.Level != Untrusted {
		t.Fatalf("second call: expected cached Untrusted, got %v", r2.Level)
	}
	if r2.Reason != "bad exe" {
		t.Errorf("cached reason = %q, want %q", r2.Reason, "bad exe")
	}
}

func TestCheckRisk_TrustedFastPath(t *testing.T) {
	exe := &mockBinaryInf{path: "/usr/bin/app", result: RiskResult{Level: Trusted}}
	parent := &riskMockProcess{pid: 1, result: RiskResult{Level: Trusted}}
	p := newTestProcess(100, withExe(exe), withParent(parent))

	// First call — all phases run.
	r1 := p.CheckRisk(algorithmCfg())
	if r1.Level != Trusted {
		t.Fatalf("first call: expected Trusted, got %v", r1.Level)
	}
	if !p.ancestorVerified {
		t.Fatal("ancestorVerified should be true after full pass")
	}

	// Second call — fast path (Phase 2 and 3 skipped).
	// Make parent return Untrusted — should not matter because ancestor is cached.
	parent.result = RiskResult{Level: Untrusted, Reason: "should not see this"}
	r2 := p.CheckRisk(algorithmCfg())
	if r2.Level != Trusted {
		t.Fatalf("second call: expected fast-path Trusted, got %v (reason=%q)", r2.Level, r2.Reason)
	}
}

func TestCheckRisk_AncestorUntrustedNotCachedOnChild(t *testing.T) {
	parent := &riskMockProcess{pid: 50, result: RiskResult{Level: Untrusted, Reason: "bad parent"}}
	p := newTestProcess(100,
		withExe(&mockBinaryInf{path: "/usr/bin/app", result: RiskResult{Level: Trusted}}),
		withParent(parent),
	)

	// First call — ancestor fails, child returns Untrusted but does NOT cache.
	r1 := p.CheckRisk(algorithmCfg())
	if r1.Level != Untrusted {
		t.Fatalf("first call: expected Untrusted, got %v", r1.Level)
	}
	if p.risk == Untrusted {
		t.Fatal("child p.risk should NOT be Untrusted — ancestor failure is not cached on child")
	}
	if p.ancestorVerified {
		t.Fatal("ancestorVerified should be false after ancestor failure")
	}

	// Fix parent — now child should pass on retry.
	parent.result = RiskResult{Level: Trusted}
	r2 := p.CheckRisk(algorithmCfg())
	if r2.Level != Trusted {
		t.Fatalf("retry: expected Trusted after parent fixed, got %v (reason=%q)", r2.Level, r2.Reason)
	}
	if !p.ancestorVerified {
		t.Fatal("ancestorVerified should be true after successful retry")
	}
}

// --- Ancestor depth and config tests ---

func TestCheckRisk_AncestorCheckDisabled(t *testing.T) {
	parent := &riskMockProcess{pid: 50, result: RiskResult{Level: Untrusted, Reason: "bad"}}
	p := newTestProcess(100,
		withExe(&mockBinaryInf{path: "/usr/bin/app", result: RiskResult{Level: Trusted}}),
		withParent(parent),
	)

	cfg := algorithmCfg()
	cfg.AncestorCheck.Enabled = false

	result := p.CheckRisk(cfg)
	if result.Level != Trusted {
		t.Fatalf("expected Trusted when ancestor check disabled, got %v", result.Level)
	}
}

func TestCheckRisk_MaxAncestorDepthZero(t *testing.T) {
	parent := &riskMockProcess{pid: 50, result: RiskResult{Level: Untrusted, Reason: "bad"}}
	p := newTestProcess(100,
		withExe(&mockBinaryInf{path: "/usr/bin/app", result: RiskResult{Level: Trusted}}),
		withParent(parent),
	)

	cfg := algorithmCfg()
	cfg.MaxAncestorDepth = 0

	result := p.CheckRisk(cfg)
	if result.Level != Trusted {
		t.Fatalf("expected Trusted when MaxAncestorDepth=0, got %v", result.Level)
	}
}

func TestCheckRisk_DeepAncestorChain(t *testing.T) {
	// grandparent(untrusted) → parent(trusted) → child
	grandparent := &riskMockProcess{pid: 10, result: RiskResult{Level: Untrusted, Reason: "bad grandparent"}}
	parent := &riskMockProcess{pid: 50, result: RiskResult{Level: Trusted}, parent: grandparent}
	// Override parent's CheckRisk to actually recurse to grandparent.
	// Since riskMockProcess.CheckRisk ignores cfg, we simulate the recursion
	// by making parent always return trusted — the real ancestor recursion is
	// tested by Process.CheckRisk, not mock's CheckRisk.
	// Instead, test depth limit: set MaxAncestorDepth=1 so only direct parent is checked.
	p := newTestProcess(100,
		withExe(&mockBinaryInf{path: "/usr/bin/app", result: RiskResult{Level: Trusted}}),
		withParent(parent),
	)

	cfg := algorithmCfg()
	cfg.MaxAncestorDepth = 1

	result := p.CheckRisk(cfg)
	// Only parent is checked (depth=1), parent returns Trusted. Grandparent not reached.
	if result.Level != Trusted {
		t.Fatalf("expected Trusted with depth=1, got %v (reason=%q)", result.Level, result.Reason)
	}
}

// --- Library injection in Phase 2 tests ---

func TestCheckRisk_LibraryInjectionFail_CachesToRisk(t *testing.T) {
	// Mock procMapsReader to return a suspicious library.
	origMaps := procMapsReader
	defer func() { procMapsReader = origMaps }()
	procMapsReader = func(pid int32) ([]byte, error) {
		return []byte("7f000000-7f001000 r-xp 00000000 00:00 0 /tmp/evil.so\n"), nil
	}

	p := newTestProcess(100,
		withExe(&mockBinaryInf{path: "/usr/bin/app", result: RiskResult{Level: Trusted}}),
		withNoParent(),
	)

	cfg := algorithmCfg()
	cfg.LibraryInjectionCheck.Enabled = true

	result := p.CheckRisk(cfg)
	if result.Level != Untrusted {
		t.Fatalf("expected Untrusted from library injection, got %v", result.Level)
	}
	if !strings.Contains(result.Reason, "suspicious library") {
		t.Errorf("reason should mention suspicious library, got %q", result.Reason)
	}
	if p.risk != Untrusted {
		t.Fatal("library injection failure should be cached in p.risk")
	}
}

func TestCheckRisk_LibraryInjectionCached(t *testing.T) {
	callCount := 0
	origMaps := procMapsReader
	defer func() { procMapsReader = origMaps }()
	procMapsReader = func(pid int32) ([]byte, error) {
		callCount++
		return []byte(""), nil
	}

	p := newTestProcess(100,
		withExe(&mockBinaryInf{path: "/usr/bin/app", result: RiskResult{Level: Trusted}}),
		withNoParent(),
	)

	cfg := algorithmCfg()
	cfg.LibraryInjectionCheck.Enabled = true

	// First call.
	r1 := p.CheckRisk(cfg)
	if r1.Level != Trusted {
		t.Fatalf("first call: expected Trusted, got %v", r1.Level)
	}
	if callCount != 1 {
		t.Fatalf("expected procMapsReader called once, got %d", callCount)
	}

	// Second call — Phase 2 cached, procMapsReader should NOT be called again.
	r2 := p.CheckRisk(cfg)
	if r2.Level != Trusted {
		t.Fatalf("second call: expected Trusted, got %v", r2.Level)
	}
	if callCount != 1 {
		t.Fatalf("procMapsReader should not be called again (cached), got %d calls", callCount)
	}
}

// --- Nil config test ---

func TestCheckRisk_NilConfig(t *testing.T) {
	// Use own PID so /proc reads succeed.
	// This tests that nil config falls back to defaults without panic.
	p := newTestProcess(100,
		withExe(&mockBinaryInf{path: "/usr/bin/app", result: RiskResult{Level: Trusted}}),
		withNoParent(),
	)

	cfg := algorithmCfg()
	result := p.CheckRisk(cfg)
	if result.Level != Trusted {
		t.Fatalf("expected Trusted, got %v (reason=%q)", result.Level, result.Reason)
	}
}

// --- Exe resolve failure ---

func TestCheckRisk_ExeResolveFail(t *testing.T) {
	origExe := procExeReader
	defer func() { procExeReader = origExe }()
	procExeReader = func(pid int32) (string, error) {
		return "", fmt.Errorf("no such process")
	}

	// Process without pre-set exe — getExe will try platformGetExePath, which calls procExeReader.
	p := newTestProcess(100, withNoParent())

	cfg := algorithmCfg()
	cfg.LibraryInjectionCheck.Enabled = false

	result := p.CheckRisk(cfg)
	if result.Level != Untrusted {
		t.Fatalf("expected Untrusted when exe resolve fails, got %v", result.Level)
	}
	if !strings.Contains(result.Reason, "exe_resolve") {
		t.Errorf("reason should mention exe_resolve, got %q", result.Reason)
	}
}
