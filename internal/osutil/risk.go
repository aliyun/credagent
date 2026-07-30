package osutil

// RiskLevel represents the trust state of a process or binary.
type RiskLevel uint

const (
	Unchecked RiskLevel = 0
	Untrusted RiskLevel = 1
	Trusted   RiskLevel = 100
	FreeCheck RiskLevel = 200 // Harness descendant — skip all checks unconditionally
)

// RiskResult holds the outcome of a risk assessment.
type RiskResult struct {
	Level  RiskLevel
	Reason string
}

// RiskCheckConfig controls which security checks are performed.
type RiskCheckConfig struct {
	BinaryCheck           BinaryCheckOpts
	ProcessStatusCheck    ProcessStatusCheckOpts
	LibraryInjectionCheck LibraryInjectionCheckOpts
	EnvVarCheck        EnvVarCheckOpts
	InterpreterCheck   map[string]InterpreterCheckOpts
	AncestorCheck         AncestorCheckOpts

	MaxAncestorDepth int

	// SkipRuntimeChecks disables per-open runtime checks (tracePid, seccomp).
	// Used for parent process checks where runtime state is less relevant.
	SkipRuntimeChecks bool

	// TrustedHarness lists exe paths of trusted process harnesses (e.g.
	// /usr/local/bin/harness). If a process's ancestor chain contains any of
	// these, the process and all intermediate ancestors are marked FreeCheck
	// (skip all risk checks unconditionally).
	TrustedHarness []string
}

// ForParent returns a cloned config suitable for ancestor checks:
// runtime checks disabled, depth decremented. BinaryCheck.TrustedPrograms is
// preserved so authorized binaries remain trusted along the whole chain.
func (c *RiskCheckConfig) ForParent() *RiskCheckConfig {
	if c == nil {
		return DefaultRiskCheckConfig()
	}
	clone := *c
	clone.SkipRuntimeChecks = true
	clone.MaxAncestorDepth = c.MaxAncestorDepth - 1
	return &clone
}

// WithTrustedPrograms returns a cloned config with extra binary paths appended
// to BinaryCheck.TrustedPrograms AND to every interpreter family's TrustedScripts.
// Used by the engine to inject baseline-authorized binaries/scripts (from
// `credctl protect -p`) before invoking process.CheckRisk.
func (c *RiskCheckConfig) WithTrustedPrograms(extras []string) *RiskCheckConfig {
	if c == nil {
		c = DefaultRiskCheckConfig()
	}
	clone := *c
	if len(extras) == 0 {
		return &clone
	}
	merged := make([]string, 0, len(c.BinaryCheck.TrustedPrograms)+len(extras))
	merged = append(merged, c.BinaryCheck.TrustedPrograms...)
	merged = append(merged, extras...)
	clone.BinaryCheck.TrustedPrograms = merged

	if clone.InterpreterCheck != nil {
		newMap := make(map[string]InterpreterCheckOpts, len(clone.InterpreterCheck))
		for family, opts := range clone.InterpreterCheck {
			mergedScripts := make([]string, 0, len(opts.TrustedScripts)+len(extras))
			mergedScripts = append(mergedScripts, opts.TrustedScripts...)
			mergedScripts = append(mergedScripts, extras...)
			opts.TrustedScripts = mergedScripts
			newMap[family] = opts
		}
		clone.InterpreterCheck = newMap
	}

	return &clone
}

// DefaultRiskCheckConfig returns a config with all checks disabled by default.
// Security checks are opt-in: they must be explicitly enabled via security.json.
// MaxAncestorDepth is kept at 5 so it is ready when ancestor_check is enabled.
func DefaultRiskCheckConfig() *RiskCheckConfig {
	return &RiskCheckConfig{
		BinaryCheck:           BinaryCheckOpts{Enabled: false},
		ProcessStatusCheck:    ProcessStatusCheckOpts{Enabled: false},
		LibraryInjectionCheck: LibraryInjectionCheckOpts{Enabled: false},
		EnvVarCheck:           EnvVarCheckOpts{Enabled: false},
		InterpreterCheck:      nil,
		AncestorCheck:         AncestorCheckOpts{Enabled: false},
		MaxAncestorDepth:      5,
		SkipRuntimeChecks:     false,
	}
}
