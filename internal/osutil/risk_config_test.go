package osutil

import "testing"

func TestDefaultRiskCheckConfig(t *testing.T) {
	cfg := DefaultRiskCheckConfig()

	if cfg.BinaryCheck.Enabled {
		t.Error("BinaryCheck should be disabled by default")
	}
	if cfg.ProcessStatusCheck.Enabled {
		t.Error("ProcessStatusCheck should be disabled by default")
	}
	if cfg.LibraryInjectionCheck.Enabled {
		t.Error("LibraryInjectionCheck should be disabled by default")
	}
	if cfg.EnvVarCheck.Enabled {
		t.Error("EnvVarCheck should be disabled by default")
	}
	if cfg.AncestorCheck.Enabled {
		t.Error("AncestorCheck should be disabled by default")
	}
	if cfg.MaxAncestorDepth != 5 {
		t.Errorf("MaxAncestorDepth = %d, want 5", cfg.MaxAncestorDepth)
	}
	if cfg.SkipRuntimeChecks {
		t.Error("SkipRuntimeChecks should be false by default")
	}
	if cfg.InterpreterCheck != nil {
		t.Error("InterpreterCheck should be nil by default")
	}
}

func TestForParent(t *testing.T) {
	cfg := DefaultRiskCheckConfig()
	cfg.BinaryCheck.Enabled = true
	cfg.BinaryCheck.TrustedPrograms = []string{"/usr/bin/python3"}
	cfg.MaxAncestorDepth = 5

	parent := cfg.ForParent()

	if !parent.SkipRuntimeChecks {
		t.Error("ForParent should set SkipRuntimeChecks=true")
	}
	if parent.MaxAncestorDepth != 4 {
		t.Errorf("ForParent MaxAncestorDepth = %d, want 4", parent.MaxAncestorDepth)
	}
	if len(parent.BinaryCheck.TrustedPrograms) != 1 || parent.BinaryCheck.TrustedPrograms[0] != "/usr/bin/python3" {
		t.Error("ForParent should preserve TrustedPrograms")
	}
	if !parent.BinaryCheck.Enabled {
		t.Error("ForParent should preserve BinaryCheck.Enabled")
	}
}

func TestForParent_NilConfig(t *testing.T) {
	var cfg *RiskCheckConfig
	parent := cfg.ForParent()
	if parent == nil {
		t.Fatal("ForParent(nil) should return default config")
	}
	if parent.MaxAncestorDepth != 5 {
		t.Errorf("ForParent(nil) MaxAncestorDepth = %d, want 5", parent.MaxAncestorDepth)
	}
}

func TestForParent_DoesNotMutateOriginal(t *testing.T) {
	cfg := DefaultRiskCheckConfig()
	cfg.MaxAncestorDepth = 3

	_ = cfg.ForParent()

	if cfg.MaxAncestorDepth != 3 {
		t.Errorf("ForParent mutated original MaxAncestorDepth: got %d, want 3", cfg.MaxAncestorDepth)
	}
	if cfg.SkipRuntimeChecks {
		t.Error("ForParent mutated original SkipRuntimeChecks")
	}
}

func TestWithTrustedPrograms(t *testing.T) {
	cfg := DefaultRiskCheckConfig()
	cfg.BinaryCheck.TrustedPrograms = []string{"/usr/bin/cat"}
	cfg.InterpreterCheck = map[string]InterpreterCheckOpts{
		"python": {Enabled: true, TrustedScripts: []string{"/opt/script.py"}},
		"node":   {Enabled: true, TrustedScripts: nil},
	}

	extras := []string{"/opt/app/bin", "/opt/app/run.py"}
	merged := cfg.WithTrustedPrograms(extras)

	wantBinary := []string{"/usr/bin/cat", "/opt/app/bin", "/opt/app/run.py"}
	if len(merged.BinaryCheck.TrustedPrograms) != len(wantBinary) {
		t.Fatalf("BinaryCheck.TrustedPrograms len = %d, want %d",
			len(merged.BinaryCheck.TrustedPrograms), len(wantBinary))
	}
	for i, v := range wantBinary {
		if merged.BinaryCheck.TrustedPrograms[i] != v {
			t.Errorf("BinaryCheck.TrustedPrograms[%d] = %q, want %q", i, merged.BinaryCheck.TrustedPrograms[i], v)
		}
	}

	pythonOpts := merged.InterpreterCheck["python"]
	wantScripts := []string{"/opt/script.py", "/opt/app/bin", "/opt/app/run.py"}
	if len(pythonOpts.TrustedScripts) != len(wantScripts) {
		t.Fatalf("python TrustedScripts len = %d, want %d",
			len(pythonOpts.TrustedScripts), len(wantScripts))
	}
	for i, v := range wantScripts {
		if pythonOpts.TrustedScripts[i] != v {
			t.Errorf("python TrustedScripts[%d] = %q, want %q", i, pythonOpts.TrustedScripts[i], v)
		}
	}

	nodeOpts := merged.InterpreterCheck["node"]
	if len(nodeOpts.TrustedScripts) != 2 {
		t.Errorf("node TrustedScripts len = %d, want 2", len(nodeOpts.TrustedScripts))
	}
}

func TestWithTrustedPrograms_EmptyExtras(t *testing.T) {
	cfg := DefaultRiskCheckConfig()
	cfg.BinaryCheck.TrustedPrograms = []string{"/usr/bin/cat"}

	merged := cfg.WithTrustedPrograms(nil)

	if len(merged.BinaryCheck.TrustedPrograms) != 1 {
		t.Errorf("WithTrustedPrograms(nil) should not change list, got len=%d", len(merged.BinaryCheck.TrustedPrograms))
	}
}

func TestWithTrustedPrograms_NilConfig(t *testing.T) {
	var cfg *RiskCheckConfig
	merged := cfg.WithTrustedPrograms([]string{"/opt/app"})

	if merged == nil {
		t.Fatal("WithTrustedPrograms(nil) should return config")
	}
	if len(merged.BinaryCheck.TrustedPrograms) != 1 || merged.BinaryCheck.TrustedPrograms[0] != "/opt/app" {
		t.Error("WithTrustedPrograms(nil) should contain the extras")
	}
}

func TestWithTrustedPrograms_DoesNotMutateOriginal(t *testing.T) {
	cfg := DefaultRiskCheckConfig()
	cfg.BinaryCheck.TrustedPrograms = []string{"/usr/bin/cat"}

	_ = cfg.WithTrustedPrograms([]string{"/opt/app"})

	if len(cfg.BinaryCheck.TrustedPrograms) != 1 {
		t.Error("WithTrustedPrograms mutated original BinaryCheck.TrustedPrograms")
	}
}
