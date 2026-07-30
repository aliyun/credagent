//go:build linux

package osutil

import (
	"fmt"
	"strings"
	"testing"
)

// mockStatus builds a fake /proc/<pid>/status content string.
func mockStatus(tracerPid int, seccompMode int) string {
	return fmt.Sprintf(`Name:	test
Umask:	0022
State:	S (sleeping)
Tgid:	1234
Pid:	1234
PPid:	1
TracerPid:	%d
Uid:	0	0	0	0
Gid:	0	0	0	0
Seccomp:	%d
`, tracerPid, seccompMode)
}

// withMockStatus sets up a procStatusReader mock and returns a cleanup func.
func withMockStatus(t *testing.T, content string) {
	t.Helper()
	orig := procStatusReader
	t.Cleanup(func() { procStatusReader = orig })
	procStatusReader = func(pid int32) (string, error) {
		return content, nil
	}
}

// withMockStatusError sets up a procStatusReader that returns an error.
func withMockStatusError(t *testing.T, err error) {
	t.Helper()
	orig := procStatusReader
	t.Cleanup(func() { procStatusReader = orig })
	procStatusReader = func(pid int32) (string, error) {
		return "", err
	}
}

// withMockMaps sets up a procMapsReader mock and returns a cleanup func.
func withMockMaps(t *testing.T, content string) {
	t.Helper()
	orig := procMapsReader
	t.Cleanup(func() { procMapsReader = orig })
	procMapsReader = func(pid int32) ([]byte, error) {
		return []byte(content), nil
	}
}

// withMockMapsError sets up a procMapsReader that returns an error.
func withMockMapsError(t *testing.T) {
	t.Helper()
	orig := procMapsReader
	t.Cleanup(func() { procMapsReader = orig })
	procMapsReader = func(pid int32) ([]byte, error) {
		return nil, fmt.Errorf("no such process")
	}
}

// --- TracerPid tests ---

func TestPlatformCheckRuntime_TracerPidZero(t *testing.T) {
	withMockStatus(t, mockStatus(0, 0))

	p := &Process{pid: 999}
	cfg := DefaultRiskCheckConfig()
	cfg.ProcessStatusCheck.Enabled = true

	result := p.platformCheckRuntime(cfg)
	if result.Level != Trusted {
		t.Fatalf("expected Trusted when TracerPid=0, got %v (reason=%q)", result.Level, result.Reason)
	}
}

func TestPlatformCheckRuntime_TracerPidNonZero(t *testing.T) {
	withMockStatus(t, mockStatus(12345, 0))

	p := &Process{pid: 999}
	cfg := DefaultRiskCheckConfig()
	cfg.ProcessStatusCheck.Enabled = true

	result := p.platformCheckRuntime(cfg)
	if result.Level != Untrusted {
		t.Fatalf("expected Untrusted when traced, got %v", result.Level)
	}
	if !strings.Contains(result.Reason, "being traced") {
		t.Errorf("reason should contain 'being traced', got %q", result.Reason)
	}
	if !strings.Contains(result.Reason, "12345") {
		t.Errorf("reason should contain tracer PID, got %q", result.Reason)
	}
}

func TestPlatformCheckRuntime_TracerPid_CheckDisabled(t *testing.T) {
	withMockStatus(t, mockStatus(12345, 0))

	p := &Process{pid: 999}
	cfg := DefaultRiskCheckConfig()
	cfg.ProcessStatusCheck.Enabled = false

	result := p.platformCheckRuntime(cfg)
	if result.Level != Trusted {
		t.Fatalf("expected Trusted when check disabled, got %v", result.Level)
	}
}

// --- Seccomp tests ---

func TestPlatformCheckRuntime_SeccompZero(t *testing.T) {
	withMockStatus(t, mockStatus(0, 0))

	p := &Process{pid: 999}
	cfg := DefaultRiskCheckConfig()
	cfg.ProcessStatusCheck.Enabled = true
	result := p.platformCheckRuntime(cfg)
	if result.Level != Trusted {
		t.Fatalf("expected Trusted when Seccomp=0, got %v", result.Level)
	}
}

func TestPlatformCheckRuntime_SeccompStrict(t *testing.T) {
	// Seccomp mode 1 (strict) should be allowed.
	withMockStatus(t, mockStatus(0, 1))

	p := &Process{pid: 999}
	cfg := DefaultRiskCheckConfig()
	cfg.ProcessStatusCheck.Enabled = true
	result := p.platformCheckRuntime(cfg)
	if result.Level != Trusted {
		t.Fatalf("expected Trusted when Seccomp=1 (strict), got %v (reason=%q)", result.Level, result.Reason)
	}
}

func TestPlatformCheckRuntime_SeccompFilter(t *testing.T) {
	withMockStatus(t, mockStatus(0, 2))

	p := &Process{pid: 999}
	cfg := DefaultRiskCheckConfig()
	cfg.ProcessStatusCheck.Enabled = true
	result := p.platformCheckRuntime(cfg)
	if result.Level != Untrusted {
		t.Fatalf("expected Untrusted when Seccomp=2, got %v", result.Level)
	}
	if !strings.Contains(result.Reason, "seccomp filter") {
		t.Errorf("reason should contain 'seccomp filter', got %q", result.Reason)
	}
}

// --- TracerPid + Seccomp combination ---

func TestPlatformCheckRuntime_TracerAndSeccomp_TracerFirst(t *testing.T) {
	withMockStatus(t, mockStatus(9999, 2))

	p := &Process{pid: 999}
	cfg := DefaultRiskCheckConfig()
	cfg.ProcessStatusCheck.Enabled = true
	result := p.platformCheckRuntime(cfg)
	if result.Level != Untrusted {
		t.Fatalf("expected Untrusted, got %v", result.Level)
	}
	// TracerPid check comes first, should short-circuit.
	if !strings.Contains(result.Reason, "being traced") {
		t.Errorf("TracerPid should be checked first, got reason=%q", result.Reason)
	}
}

// --- Status file errors ---

func TestPlatformCheckRuntime_StatusReadError(t *testing.T) {
	withMockStatusError(t, fmt.Errorf("permission denied"))

	p := &Process{pid: 999}
	cfg := DefaultRiskCheckConfig()
	cfg.ProcessStatusCheck.Enabled = true
	result := p.platformCheckRuntime(cfg)
	if result.Level != Untrusted {
		t.Fatalf("expected Untrusted when status unreadable, got %v", result.Level)
	}
	if !strings.Contains(result.Reason, "cannot read status") {
		t.Errorf("reason should mention 'cannot read status', got %q", result.Reason)
	}
}

// --- Library injection tests ---

func libInjectionCfg() *RiskCheckConfig {
	cfg := DefaultRiskCheckConfig()
	cfg.LibraryInjectionCheck.Enabled = true
	return cfg
}

func TestCheckLibraryInjection_NoSo(t *testing.T) {
	withMockMaps(t, `7f000000-7f001000 r-xp 00000000 08:01 1234 /usr/lib/x86_64-linux-gnu/libc.so.6
7f100000-7f200000 rw-p 00000000 00:00 0 [heap]
`)

	p := &Process{pid: 999}
	result := p.platformCheckLibraryInjection(libInjectionCfg())
	if result.Level != Trusted {
		t.Fatalf("expected Trusted for normal libraries, got %v (reason=%q)", result.Level, result.Reason)
	}
}

func TestCheckLibraryInjection_SuspiciousFromTmp(t *testing.T) {
	withMockMaps(t, `7f000000-7f001000 r-xp 00000000 08:01 1234 /usr/lib/libc.so.6
7f100000-7f101000 r-xp 00000000 08:01 5678 /tmp/evil.so
`)

	p := &Process{pid: 999}
	result := p.platformCheckLibraryInjection(libInjectionCfg())
	if result.Level != Untrusted {
		t.Fatalf("expected Untrusted for .so from /tmp, got %v", result.Level)
	}
	if !strings.Contains(result.Reason, "suspicious library") {
		t.Errorf("reason should mention 'suspicious library', got %q", result.Reason)
	}
	if !strings.Contains(result.Reason, "/tmp/evil.so") {
		t.Errorf("reason should contain library path, got %q", result.Reason)
	}
}

func TestCheckLibraryInjection_SuspiciousFromHome(t *testing.T) {
	withMockMaps(t, `7f000000-7f001000 r-xp 00000000 08:01 1234 /home/user/.local/lib/inject.so
`)

	p := &Process{pid: 999}
	result := p.platformCheckLibraryInjection(libInjectionCfg())
	if result.Level != Untrusted {
		t.Fatalf("expected Untrusted for .so from /home, got %v", result.Level)
	}
}

func TestCheckLibraryInjection_SuspiciousFromDevShm(t *testing.T) {
	withMockMaps(t, `7f000000-7f001000 r-xp 00000000 08:01 1234 /dev/shm/payload.so
`)

	p := &Process{pid: 999}
	result := p.platformCheckLibraryInjection(libInjectionCfg())
	if result.Level != Untrusted {
		t.Fatalf("expected Untrusted for .so from /dev/shm, got %v", result.Level)
	}
}

func TestCheckLibraryInjection_SuspiciousFromVarTmp(t *testing.T) {
	withMockMaps(t, `7f000000-7f001000 r-xp 00000000 08:01 1234 /var/tmp/stager.so
`)

	p := &Process{pid: 999}
	result := p.platformCheckLibraryInjection(libInjectionCfg())
	if result.Level != Untrusted {
		t.Fatalf("expected Untrusted for .so from /var/tmp, got %v", result.Level)
	}
}

func TestCheckLibraryInjection_SuspiciousButTrusted(t *testing.T) {
	withMockMaps(t, `7f000000-7f001000 r-xp 00000000 08:01 1234 /tmp/trusted_lib.so
`)

	p := &Process{pid: 999}
	cfg := libInjectionCfg()
	cfg.LibraryInjectionCheck.TrustedLibPaths = []string{"/tmp/trusted_lib.so"}

	result := p.platformCheckLibraryInjection(cfg)
	if result.Level != Trusted {
		t.Fatalf("expected Trusted for library in trustedLibPaths, got %v (reason=%q)", result.Level, result.Reason)
	}
}

func TestCheckLibraryInjection_Disabled(t *testing.T) {
	withMockMaps(t, `7f000000-7f001000 r-xp 00000000 08:01 1234 /tmp/evil.so
`)

	p := &Process{pid: 999}
	cfg := DefaultRiskCheckConfig()
	cfg.LibraryInjectionCheck.Enabled = false

	result := p.platformCheckLibraryInjection(cfg)
	if result.Level != Trusted {
		t.Fatalf("expected Trusted when disabled, got %v", result.Level)
	}
}

func TestCheckLibraryInjection_MapsReadError(t *testing.T) {
	withMockMapsError(t)

	p := &Process{pid: 999}
	result := p.platformCheckLibraryInjection(libInjectionCfg())
	if result.Level != Trusted {
		t.Fatalf("expected Trusted when maps unreadable (fail-open), got %v", result.Level)
	}
}

func TestCheckLibraryInjection_NormalSystemLibraries(t *testing.T) {
	withMockMaps(t, `7f000000-7f001000 r-xp 00000000 08:01 1234 /usr/lib/x86_64-linux-gnu/libc.so.6
7f100000-7f101000 r-xp 00000000 08:01 2345 /usr/lib/x86_64-linux-gnu/libpthread.so.0
7f200000-7f201000 r-xp 00000000 08:01 3456 /lib/x86_64-linux-gnu/libdl.so.2
`)

	p := &Process{pid: 999}
	result := p.platformCheckLibraryInjection(libInjectionCfg())
	if result.Level != Trusted {
		t.Fatalf("expected Trusted for normal system libs, got %v (reason=%q)", result.Level, result.Reason)
	}
}

func TestCheckLibraryInjection_MixedNormalAndSuspicious(t *testing.T) {
	withMockMaps(t, `7f000000-7f001000 r-xp 00000000 08:01 1234 /usr/lib/x86_64-linux-gnu/libc.so.6
7f100000-7f101000 r-xp 00000000 08:01 2345 /usr/lib/libssl.so.3
7f200000-7f201000 r-xp 00000000 08:01 3456 /dev/shm/inject.so
7f300000-7f301000 r-xp 00000000 08:01 4567 /usr/lib/libcrypto.so.3
`)

	p := &Process{pid: 999}
	result := p.platformCheckLibraryInjection(libInjectionCfg())
	if result.Level != Untrusted {
		t.Fatalf("expected Untrusted (suspicious lib mixed in), got %v", result.Level)
	}
	if !strings.Contains(result.Reason, "/dev/shm/inject.so") {
		t.Errorf("reason should identify the suspicious lib, got %q", result.Reason)
	}
}

func TestCheckLibraryInjection_SoVersionedName(t *testing.T) {
	// Versioned .so names like libevil.so.1 should also be caught.
	withMockMaps(t, `7f000000-7f001000 r-xp 00000000 08:01 1234 /tmp/libevil.so.1
`)

	p := &Process{pid: 999}
	result := p.platformCheckLibraryInjection(libInjectionCfg())
	if result.Level != Untrusted {
		t.Fatalf("expected Untrusted for versioned .so in /tmp, got %v", result.Level)
	}
}

func TestCheckLibraryInjection_NonLibraryMappings(t *testing.T) {
	// Entries without .so should be ignored even if from suspicious paths.
	withMockMaps(t, `7f000000-7f001000 r-xp 00000000 08:01 1234 /tmp/data.txt
7f100000-7f101000 rw-p 00000000 00:00 0 [stack]
7f200000-7f201000 r--p 00000000 08:01 2345 /home/user/config.bin
`)

	p := &Process{pid: 999}
	result := p.platformCheckLibraryInjection(libInjectionCfg())
	if result.Level != Trusted {
		t.Fatalf("expected Trusted (no .so entries), got %v (reason=%q)", result.Level, result.Reason)
	}
}

func TestCheckLibraryInjection_MultipleTrusted(t *testing.T) {
	withMockMaps(t, `7f000000-7f001000 r-xp 00000000 08:01 1234 /tmp/agent_a.so
7f100000-7f101000 r-xp 00000000 08:01 2345 /home/user/agent_b.so
`)

	p := &Process{pid: 999}
	cfg := libInjectionCfg()
	cfg.LibraryInjectionCheck.TrustedLibPaths = []string{"/tmp/agent_a.so", "/home/user/agent_b.so"}

	result := p.platformCheckLibraryInjection(cfg)
	if result.Level != Trusted {
		t.Fatalf("expected Trusted when all suspicious libs are in trusted list, got %v (reason=%q)", result.Level, result.Reason)
	}
}

func TestCheckLibraryInjection_OneOfMultipleUntrusted(t *testing.T) {
	withMockMaps(t, `7f000000-7f001000 r-xp 00000000 08:01 1234 /tmp/trusted_agent.so
7f100000-7f101000 r-xp 00000000 08:01 2345 /tmp/evil.so
`)

	p := &Process{pid: 999}
	cfg := libInjectionCfg()
	cfg.LibraryInjectionCheck.TrustedLibPaths = []string{"/tmp/trusted_agent.so"}

	result := p.platformCheckLibraryInjection(cfg)
	if result.Level != Untrusted {
		t.Fatalf("expected Untrusted (one lib not in trusted), got %v", result.Level)
	}
	if !strings.Contains(result.Reason, "/tmp/evil.so") {
		t.Errorf("reason should identify the untrusted lib, got %q", result.Reason)
	}
}

// --- Integration: Process.CheckRisk with runtime checks via mocks ---

func TestCheckRisk_RuntimeFail_Phase2NotReached(t *testing.T) {
	withMockStatus(t, mockStatus(9999, 0))

	exe := &mockBinaryInf{path: "/usr/bin/app", result: RiskResult{Level: Trusted}}
	p := newTestProcess(100, withExe(exe), withNoParent())

	cfg := DefaultRiskCheckConfig()
	cfg.ProcessStatusCheck.Enabled = true
	cfg.LibraryInjectionCheck.Enabled = false

	result := p.CheckRisk(cfg)
	if result.Level != Untrusted {
		t.Fatalf("expected Untrusted from runtime (tracer), got %v", result.Level)
	}
	if !strings.Contains(result.Reason, "being traced") {
		t.Errorf("reason = %q, want 'being traced'", result.Reason)
	}
	// Phase 2 should NOT have run — p.risk should still be Unchecked.
	if p.risk != Unchecked {
		t.Errorf("p.risk = %v, want Unchecked (Phase 2 should not run after runtime fail)", p.risk)
	}
}

func TestCheckRisk_RuntimePass_Phase2Runs(t *testing.T) {
	withMockStatus(t, mockStatus(0, 0))

	exe := &mockBinaryInf{path: "/usr/bin/app", result: RiskResult{Level: Trusted}}
	p := newTestProcess(100, withExe(exe), withNoParent())

	cfg := DefaultRiskCheckConfig()
	cfg.ProcessStatusCheck.Enabled = true
	cfg.LibraryInjectionCheck.Enabled = false

	result := p.CheckRisk(cfg)
	if result.Level != Trusted {
		t.Fatalf("expected Trusted, got %v (reason=%q)", result.Level, result.Reason)
	}
	if p.risk != Trusted {
		t.Errorf("p.risk = %v, want Trusted (Phase 2 should have run)", p.risk)
	}
}

func TestCheckRisk_RuntimeCheckEveryCall(t *testing.T) {
	// First call: no tracer → pass.
	callCount := 0
	orig := procStatusReader
	defer func() { procStatusReader = orig }()
	procStatusReader = func(pid int32) (string, error) {
		callCount++
		if callCount == 1 {
			return mockStatus(0, 0), nil
		}
		return mockStatus(55555, 0), nil
	}

	exe := &mockBinaryInf{path: "/usr/bin/app", result: RiskResult{Level: Trusted}}
	p := newTestProcess(100, withExe(exe), withNoParent())

	cfg := DefaultRiskCheckConfig()
	cfg.ProcessStatusCheck.Enabled = true
	cfg.LibraryInjectionCheck.Enabled = false

	r1 := p.CheckRisk(cfg)
	if r1.Level != Trusted {
		t.Fatalf("first call: expected Trusted, got %v", r1.Level)
	}

	// Second call: tracer attached → runtime fails (even though Phase 2 cached Trusted).
	r2 := p.CheckRisk(cfg)
	if r2.Level != Untrusted {
		t.Fatalf("second call: expected Untrusted (tracer appeared), got %v", r2.Level)
	}
	if !strings.Contains(r2.Reason, "being traced") {
		t.Errorf("reason = %q, want 'being traced'", r2.Reason)
	}
}
