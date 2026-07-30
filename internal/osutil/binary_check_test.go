//go:build linux

package osutil

import (
	"os"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	SetSystemPATH("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
	m.Run()
}

// --- checkPathTrust tests ---

func TestCheckPathTrust_Disabled(t *testing.T) {
	b := &Binary{path: "/tmp/anything", pid: 0}
	cfg := &RiskCheckConfig{BinaryCheck: BinaryCheckOpts{Enabled: false}}

	result := b.checkPathTrust(cfg)
	if result.Level != Trusted {
		t.Fatalf("expected Trusted when BinaryCheck disabled, got %v", result.Level)
	}
}

func TestCheckPathTrust_InSystemPATH(t *testing.T) {
	b := &Binary{path: "/usr/bin/cat", pid: 0}
	cfg := DefaultRiskCheckConfig()
	cfg.BinaryCheck.Enabled = true

	result := b.checkPathTrust(cfg)
	if result.Level != Trusted {
		t.Fatalf("expected Trusted for /usr/bin/cat (in PATH), got %v (reason=%q)", result.Level, result.Reason)
	}
}

func TestCheckPathTrust_InTrustedPrograms(t *testing.T) {
	b := &Binary{path: "/opt/custom/myapp", pid: 0}
	cfg := DefaultRiskCheckConfig()
	cfg.BinaryCheck.Enabled = true
	cfg.BinaryCheck.TrustedPrograms = []string{"/opt/custom/myapp"}

	result := b.checkPathTrust(cfg)
	if result.Level != Trusted {
		t.Fatalf("expected Trusted for path in TrustedPrograms, got %v", result.Level)
	}
}

func TestCheckPathTrust_UnsafePrefixes(t *testing.T) {
	cases := []struct {
		name string
		path string
	}{
		{"tmp", "/tmp/evil"},
		{"var_tmp", "/var/tmp/evil"},
		{"dev_shm", "/dev/shm/evil"},
		{"home", "/home/user/evil"},
		{"run_user", "/run/user/1000/evil"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := &Binary{path: tc.path, pid: 0}
			cfg := DefaultRiskCheckConfig()
			cfg.BinaryCheck.Enabled = true

			result := b.checkPathTrust(cfg)
			if result.Level != Untrusted {
				t.Fatalf("expected Untrusted for %s, got %v", tc.path, result.Level)
			}
			if !strings.Contains(result.Reason, "unsafe location") {
				t.Errorf("reason should contain 'unsafe location', got %q", result.Reason)
			}
			if !strings.Contains(result.Reason, tc.path) {
				t.Errorf("reason should contain path %q, got %q", tc.path, result.Reason)
			}
		})
	}
}

func TestCheckPathTrust_SystemBinary_RootOwned(t *testing.T) {
	// /usr/bin/cat should be root-owned and pass strict path check.
	// Skip if running in unusual environment where /usr/bin/cat doesn't exist.
	if _, err := os.Stat("/usr/bin/cat"); err != nil {
		t.Skip("/usr/bin/cat not found")
	}
	b := &Binary{path: "/usr/bin/cat", pid: 0}
	cfg := DefaultRiskCheckConfig()
	cfg.BinaryCheck.Enabled = true

	result := b.checkPathTrust(cfg)
	if result.Level != Trusted {
		t.Fatalf("expected Trusted for /usr/bin/cat, got %v (reason=%q)", result.Level, result.Reason)
	}
}

func TestCheckPathTrust_NotRootOwned(t *testing.T) {
	// Create a temp file — it will be owned by current (non-root) user.
	tmp, err := os.CreateTemp("", "osutil-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())
	tmp.Close()

	// The file is NOT in an unsafe prefix (it's in os.TempDir which might be /tmp,
	// but that IS an unsafe prefix). Use the file path directly — it should be caught
	// by the unsafe prefix check first.
	// To test the root-owned check specifically, we need a file NOT in unsafe prefix.
	// Skip this test if we can't create such a file. In practice, files created by
	// non-root users in /usr/local/... would fail, but we can't create them without root.
	t.Run("via_unsafe_prefix", func(t *testing.T) {
		b := &Binary{path: tmp.Name(), pid: 0}
		cfg := DefaultRiskCheckConfig()
		cfg.BinaryCheck.Enabled = true
		result := b.checkPathTrust(cfg)
		if result.Level != Untrusted {
			t.Fatalf("expected Untrusted for user-owned temp file, got %v", result.Level)
		}
	})
}

// --- Ownership check tests ---

func TestCheckPathTrust_NonExistentFile(t *testing.T) {
	// A binary that doesn't exist — cannot stat, should be untrusted.
	b := &Binary{path: "/opt/nonexistent/tool", pid: 0}
	cfg := DefaultRiskCheckConfig()
	cfg.BinaryCheck.Enabled = true

	result := b.checkPathTrust(cfg)
	if result.Level != Untrusted {
		t.Fatalf("expected Untrusted for non-existent binary, got %v", result.Level)
	}
	if !strings.Contains(result.Reason, "cannot stat") {
		t.Errorf("reason should mention cannot stat, got %q", result.Reason)
	}
}

func TestCheckPathTrust_RootOwned_NotWritable(t *testing.T) {
	// /usr/lib or similar root-owned binary not in PATH should pass ownership check.
	// Use a known root-owned file outside standard PATH dirs.
	candidates := []string{"/usr/lib/os-release", "/etc/hostname"}
	var path string
	for _, c := range candidates {
		info, err := os.Lstat(c)
		if err != nil {
			continue
		}
		if info.Mode()&0022 == 0 {
			path = c
			break
		}
	}
	if path == "" {
		t.Skip("no suitable root-owned non-writable file found outside PATH")
	}
	b := &Binary{path: path, pid: 0}
	cfg := DefaultRiskCheckConfig()
	cfg.BinaryCheck.Enabled = true

	result := b.checkPathTrust(cfg)
	if result.Level != Trusted {
		t.Fatalf("expected Trusted for root-owned non-writable file %s, got %v (reason=%q)", path, result.Level, result.Reason)
	}
}

func TestCheckPathTrust_NotRootOwned_Rejected(t *testing.T) {
	// Create a temp file in a non-unsafe location — it will be owned by current user.
	// Since we can't easily create files outside unsafe prefixes without root,
	// test via the unsafe prefix path which hits earlier.
	tmp, err := os.CreateTemp("", "osutil-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())
	tmp.Close()

	b := &Binary{path: tmp.Name(), pid: 0}
	cfg := DefaultRiskCheckConfig()
	cfg.BinaryCheck.Enabled = true
	result := b.checkPathTrust(cfg)
	if result.Level != Untrusted {
		t.Fatalf("expected Untrusted for user-owned file in /tmp, got %v", result.Level)
	}
}

// --- checkNativeEnvRisk tests (pure function) ---

func TestCheckNativeEnvRisk_Empty(t *testing.T) {
	result := checkNativeEnvRisk(nil, nil)
	if result.Level != Trusted {
		t.Fatalf("expected Trusted for empty env, got %v", result.Level)
	}
}

func TestCheckNativeEnvRisk_NoDangerous(t *testing.T) {
	envVars := []string{"HOME=/root", "PATH=/usr/bin", "TERM=xterm"}
	result := checkNativeEnvRisk(envVars, nil)
	if result.Level != Trusted {
		t.Fatalf("expected Trusted for benign env, got %v", result.Level)
	}
}

func TestCheckNativeEnvRisk_LdPreload(t *testing.T) {
	envVars := []string{"HOME=/root", "LD_PRELOAD=/tmp/evil.so", "PATH=/usr/bin"}
	result := checkNativeEnvRisk(envVars, nil)
	if result.Level != Untrusted {
		t.Fatalf("expected Untrusted for LD_PRELOAD, got %v", result.Level)
	}
	if !strings.Contains(result.Reason, "LD_PRELOAD") {
		t.Errorf("reason should mention LD_PRELOAD, got %q", result.Reason)
	}
	if !strings.Contains(result.Reason, "dangerous environment variable") {
		t.Errorf("reason should mention 'dangerous environment variable', got %q", result.Reason)
	}
}

func TestCheckNativeEnvRisk_LdLibraryPath(t *testing.T) {
	envVars := []string{"LD_LIBRARY_PATH=/tmp/libs"}
	result := checkNativeEnvRisk(envVars, nil)
	if result.Level != Untrusted {
		t.Fatalf("expected Untrusted for LD_LIBRARY_PATH, got %v", result.Level)
	}
	if !strings.Contains(result.Reason, "LD_LIBRARY_PATH") {
		t.Errorf("reason should mention LD_LIBRARY_PATH, got %q", result.Reason)
	}
}

func TestCheckNativeEnvRisk_LdAudit(t *testing.T) {
	envVars := []string{"LD_AUDIT=/tmp/audit.so"}
	result := checkNativeEnvRisk(envVars, nil)
	if result.Level != Untrusted {
		t.Fatalf("expected Untrusted for LD_AUDIT, got %v", result.Level)
	}
}

func TestCheckNativeEnvRisk_TrustedValue(t *testing.T) {
	envVars := []string{"LD_PRELOAD=/usr/lib/trusted.so"}
	trustedEnv := map[string][]string{
		"LD_PRELOAD": {"/usr/lib/trusted.so"},
	}
	result := checkNativeEnvRisk(envVars, trustedEnv)
	if result.Level != Trusted {
		t.Fatalf("expected Trusted for trusted LD_PRELOAD value, got %v (reason=%q)", result.Level, result.Reason)
	}
}

func TestCheckNativeEnvRisk_UntrustedValue(t *testing.T) {
	envVars := []string{"LD_PRELOAD=/tmp/evil.so"}
	trustedEnv := map[string][]string{
		"LD_PRELOAD": {"/usr/lib/trusted.so"},
	}
	result := checkNativeEnvRisk(envVars, trustedEnv)
	if result.Level != Untrusted {
		t.Fatalf("expected Untrusted for non-trusted LD_PRELOAD value, got %v", result.Level)
	}
}

func TestCheckNativeEnvRisk_EmptyEnvVar(t *testing.T) {
	envVars := []string{"", "HOME=/root", ""}
	result := checkNativeEnvRisk(envVars, nil)
	if result.Level != Trusted {
		t.Fatalf("expected Trusted, empty env vars should be skipped, got %v", result.Level)
	}
}

func TestCheckNativeEnvRisk_MultipleDangerous_FirstReported(t *testing.T) {
	envVars := []string{"LD_PRELOAD=/tmp/a.so", "LD_AUDIT=/tmp/b.so"}
	result := checkNativeEnvRisk(envVars, nil)
	if result.Level != Untrusted {
		t.Fatalf("expected Untrusted, got %v", result.Level)
	}
	if !strings.Contains(result.Reason, "LD_PRELOAD") {
		t.Errorf("first dangerous env var should be reported, got %q", result.Reason)
	}
}

// --- isEnvVarTrusted tests ---

func TestIsEnvVarTrusted(t *testing.T) {
	cases := []struct {
		name    string
		envVar  string
		prefix  string
		trusted map[string][]string
		want    bool
	}{
		{"nil map", "LD_PRELOAD=/x", "LD_PRELOAD=", nil, false},
		{"no key", "LD_PRELOAD=/x", "LD_PRELOAD=", map[string][]string{}, false},
		{"match", "LD_PRELOAD=/usr/lib/x.so", "LD_PRELOAD=", map[string][]string{"LD_PRELOAD": {"/usr/lib/x.so"}}, true},
		{"no match", "LD_PRELOAD=/tmp/evil.so", "LD_PRELOAD=", map[string][]string{"LD_PRELOAD": {"/usr/lib/x.so"}}, false},
		{"multiple trusted", "LD_PRELOAD=/b", "LD_PRELOAD=", map[string][]string{"LD_PRELOAD": {"/a", "/b"}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isEnvVarTrusted(tc.envVar, tc.prefix, tc.trusted)
			if got != tc.want {
				t.Errorf("isEnvVarTrusted(%q, %q) = %v, want %v", tc.envVar, tc.prefix, got, tc.want)
			}
		})
	}
}

// --- isTrustedProgram tests ---

func TestIsTrustedProgram(t *testing.T) {
	trusted := []string{"/usr/bin/cat", "/opt/app/run"}
	if !isTrustedProgram("/usr/bin/cat", trusted) {
		t.Error("expected /usr/bin/cat to be trusted")
	}
	if isTrustedProgram("/usr/bin/dog", trusted) {
		t.Error("expected /usr/bin/dog to NOT be trusted")
	}
	if isTrustedProgram("/usr/bin/cat", nil) {
		t.Error("nil trusted list should return false")
	}
}

// --- Binary.CheckRisk combined tests ---

func TestBinaryCheckRisk_PathTrusted_NoEnv(t *testing.T) {
	b := &Binary{path: "/usr/bin/cat", pid: 0}
	cfg := DefaultRiskCheckConfig()
	cfg.BinaryCheck.Enabled = true
	cfg.EnvVarCheck.Enabled = false

	result := b.CheckRisk(cfg)
	if result.Level != Trusted {
		t.Fatalf("expected Trusted, got %v (reason=%q)", result.Level, result.Reason)
	}
}

func TestBinaryCheckRisk_PathTrusted_DangerousEnv(t *testing.T) {
	origEnviron := procEnvironReader
	defer func() { procEnvironReader = origEnviron }()
	procEnvironReader = func(pid int32) ([]string, error) {
		return []string{"LD_PRELOAD=/tmp/evil.so", "HOME=/root"}, nil
	}

	b := &Binary{path: "/usr/bin/cat", pid: 1}
	cfg := DefaultRiskCheckConfig()
	cfg.BinaryCheck.Enabled = true
	cfg.EnvVarCheck.Enabled = true

	result := b.CheckRisk(cfg)
	if result.Level != Untrusted {
		t.Fatalf("expected Untrusted for dangerous env, got %v", result.Level)
	}
	if !strings.Contains(result.Reason, "LD_PRELOAD") {
		t.Errorf("reason should mention LD_PRELOAD, got %q", result.Reason)
	}
}

func TestBinaryCheckRisk_PathUntrusted_ShortCircuits(t *testing.T) {
	// If path is untrusted, env check should not even run.
	envChecked := false
	origEnviron := procEnvironReader
	defer func() { procEnvironReader = origEnviron }()
	procEnvironReader = func(pid int32) ([]string, error) {
		envChecked = true
		return []string{"LD_PRELOAD=/tmp/evil.so"}, nil
	}

	b := &Binary{path: "/tmp/evil_binary", pid: 1}
	cfg := DefaultRiskCheckConfig()
	cfg.BinaryCheck.Enabled = true

	result := b.CheckRisk(cfg)
	if result.Level != Untrusted {
		t.Fatalf("expected Untrusted, got %v", result.Level)
	}
	if envChecked {
		t.Error("env check should not run when path trust fails (short-circuit)")
	}
}

func TestBinaryCheckRisk_EnvCheckDisabled(t *testing.T) {
	origEnviron := procEnvironReader
	defer func() { procEnvironReader = origEnviron }()
	procEnvironReader = func(pid int32) ([]string, error) {
		return []string{"LD_PRELOAD=/tmp/evil.so"}, nil
	}

	b := &Binary{path: "/usr/bin/cat", pid: 1}
	cfg := DefaultRiskCheckConfig()
	cfg.BinaryCheck.Enabled = true
	cfg.EnvVarCheck.Enabled = false

	result := b.CheckRisk(cfg)
	if result.Level != Trusted {
		t.Fatalf("expected Trusted when env check disabled, got %v (reason=%q)", result.Level, result.Reason)
	}
}

// --- CheckScriptPathTrust tests ---

func TestCheckScriptPathTrust_UnsafeLocations(t *testing.T) {
	cases := []struct {
		path string
	}{
		{"/tmp/evil.py"},
		{"/var/tmp/evil.sh"},
		{"/dev/shm/payload.pl"},
		{"/home/user/script.rb"},
		{"/run/user/1000/x.js"},
	}
	for _, tc := range cases {
		result := CheckScriptPathTrust(tc.path, "", nil)
		if result.Level != Untrusted {
			t.Errorf("CheckScriptPathTrust(%q) = Trusted, want Untrusted", tc.path)
		}
		if !strings.Contains(result.Reason, "unsafe location") {
			t.Errorf("reason for %q should contain 'unsafe location', got %q", tc.path, result.Reason)
		}
	}
}

func TestCheckScriptPathTrust_TrustedViaAllowlist(t *testing.T) {
	result := CheckScriptPathTrust("/tmp/special.py", "", []string{"/tmp/special.py"})
	if result.Level != Trusted {
		t.Fatalf("expected Trusted via allowlist, got %v (reason=%q)", result.Level, result.Reason)
	}
}

func TestCheckScriptPathTrust_NonExistent(t *testing.T) {
	// Script not in trusted list, not in unsafe prefix, file doesn't exist — denied via stat.
	result := CheckScriptPathTrust("/usr/local/custom/script.py", "", nil)
	if result.Level != Untrusted {
		t.Fatalf("expected Untrusted for non-existent script, got %v", result.Level)
	}
	if !strings.Contains(result.Reason, "script_trust_check") {
		t.Errorf("reason should contain 'script_trust_check', got %q", result.Reason)
	}
}

func TestCheckScriptPathTrust_RootOwned_Trusted(t *testing.T) {
	// A root-owned script in a safe location should pass via ownership check.
	// Use a known root-owned file that exists.
	candidates := []string{"/usr/lib/os-release", "/etc/hostname"}
	var path string
	for _, c := range candidates {
		info, err := os.Lstat(c)
		if err != nil {
			continue
		}
		if info.Mode()&0022 == 0 {
			path = c
			break
		}
	}
	if path == "" {
		t.Skip("no suitable root-owned file found for test")
	}
	result := CheckScriptPathTrust(path, "", nil)
	if result.Level != Trusted {
		t.Fatalf("expected Trusted for root-owned file %s via ownership, got %v (reason=%q)", path, result.Level, result.Reason)
	}
}

func TestCheckScriptPathTrust_UnsafePrefixTakesPriority(t *testing.T) {
	// Unsafe prefix rejects even without ownership check — never reaches checkPathNodeChain.
	result := CheckScriptPathTrust("/tmp/root_owned_script.py", "", nil)
	if result.Level != Untrusted {
		t.Fatalf("expected Untrusted for /tmp path, got %v", result.Level)
	}
	if !strings.Contains(result.Reason, "unsafe location") {
		t.Errorf("reason should mention 'unsafe location', got %q", result.Reason)
	}
}

func TestCheckScriptPathTrust_AllowlistOverridesUnsafe(t *testing.T) {
	// Trusted list takes priority even for unsafe locations.
	result := CheckScriptPathTrust("/tmp/special.py", "", []string{"/tmp/special.py"})
	if result.Level != Trusted {
		t.Fatalf("expected Trusted via allowlist despite unsafe prefix, got %v (reason=%q)", result.Level, result.Reason)
	}
}

// --- checkPathNodeChain tests ---

func TestCheckPathNodeChain_RootPath(t *testing.T) {
	// "/" itself should be root-owned.
	result := checkPathNodeChain("/")
	if result.Level != Trusted {
		t.Fatalf("expected Trusted for /, got %v (reason=%q)", result.Level, result.Reason)
	}
}

func TestCheckPathNodeChain_SystemBinary(t *testing.T) {
	// /usr/bin/cat — entire chain should be root-owned.
	if _, err := os.Stat("/usr/bin/cat"); err != nil {
		t.Skip("/usr/bin/cat not found")
	}
	result := checkPathNodeChain("/usr/bin/cat")
	if result.Level != Trusted {
		t.Fatalf("expected Trusted for /usr/bin/cat chain, got %v (reason=%q)", result.Level, result.Reason)
	}
}

func TestCheckPathNodeChain_NonExistentPath(t *testing.T) {
	result := checkPathNodeChain("/opt/no/such/file")
	if result.Level != Untrusted {
		t.Fatalf("expected Untrusted for non-existent path, got %v", result.Level)
	}
	if !strings.Contains(result.Reason, "cannot stat") {
		t.Errorf("reason should mention 'cannot stat', got %q", result.Reason)
	}
}

func TestCheckPathNodeChain_UserOwnedParent(t *testing.T) {
	// /home/user/... — /home is typically root but /home/user is user-owned.
	// This hits the unsafe prefix check before reaching checkPathNodeChain in the
	// actual flow, but we test the function directly here.
	result := checkPathNodeChain("/home")
	// /home itself should be root-owned on most systems.
	if _, err := os.Stat("/home"); err != nil {
		t.Skip("/home not found")
	}
	// We just verify it doesn't panic; actual result depends on system state.
	_ = result
}
