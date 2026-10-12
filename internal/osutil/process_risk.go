package osutil

import "github.com/aliyun/credagent/pkg/logger"

// CheckRisk performs a full risk assessment of the process:
//  0. FreeCheck fast path — harness descendant, skip everything
//  1. Runtime checks (TracerPid, seccomp) - every call
//  2. One-time checks (library injection, exe trust via Binary/Interpreter.CheckRisk) - cached via p.risk
//  3. Recursive ancestor check - cached via p.ancestorVerified
//
// Short-circuits:
//   - FreeCheck is the highest trust: once p.risk == FreeCheck, every call returns Trusted immediately.
//   - Untrusted result is sticky: once p.risk == Untrusted, every call returns it.
//   - Trusted + ancestorVerified: only Phase 1 runtime check runs (still fresh
//     each call); Phases 2 and 3 are skipped entirely.
//
// The ancestor short-circuit is safe because cfg.BinaryCheck.TrustedPrograms is
// monotonic (engine only appends per-baseline AllowedPrograms via
// WithTrustedPrograms) — a process that passed under one cfg cannot fail under
// a cfg that adds more trusted programs.
func (p *Process) CheckRisk(cfg *RiskCheckConfig) RiskResult {
	if cfg == nil {
		cfg = DefaultRiskCheckConfig()
	}

	// Phase 0: FreeCheck — harness or harness descendant, skip all checks.
	if p.risk == FreeCheck {
		logger.Debug("[Process.CheckRisk] FREECHECK pid=%d (harness descendant)", p.pid)
		return RiskResult{Level: Trusted}
	}
	if len(cfg.TrustedHarness) > 0 {
		// Check if this process itself IS a harness — stops Phase 3 recursion at harness boundary.
		if exePath, err := p.platformGetExePath(); err == nil && isInTrustedHarness(exePath, cfg.TrustedHarness) {
			p.risk = FreeCheck
			logger.Debug("[Process.CheckRisk] FREECHECK pid=%d (is harness: %s)", p.pid, exePath)
			return RiskResult{Level: Trusted}
		}
		// Check if any ancestor is a harness — marks the entire chain below as FreeCheck.
		if p.hasTrustedHarnessAncestor(cfg) {
			logger.Debug("[Process.CheckRisk] FREECHECK pid=%d (harness ancestor found, marked)", p.pid)
			return RiskResult{Level: Trusted}
		}
	}

	logger.Debug("[Process.CheckRisk] enter pid=%d depth=%d skipRuntime=%v risk=%d ancestorVerified=%v",
		p.pid, cfg.MaxAncestorDepth, cfg.SkipRuntimeChecks, p.risk, p.ancestorVerified)

	// Phase 1: Runtime checks (state can change between opens; never cached).
	if !cfg.SkipRuntimeChecks {
		if result := p.platformCheckRuntime(cfg); result.Level == Untrusted {
			logger.Debug("[Process.CheckRisk] FAIL runtime pid=%d reason=%q", p.pid, result.Reason)
			return result
		}
	}

	if p.risk == Untrusted {
		logger.Debug("[Process.CheckRisk] CACHE-HIT pid=%d untrusted reason=%q", p.pid, p.riskReason)
		return RiskResult{Level: Untrusted, Reason: p.riskReason}
	}

	// Fast path: full chain previously verified — skip Phase 2 and Phase 3.
	if p.risk == Trusted && p.ancestorVerified {
		logger.Debug("[Process.CheckRisk] FAST-PATH pid=%d (one-time + ancestor cached)", p.pid)
		return RiskResult{Level: Trusted}
	}

	// Phase 2: One-time checks (cached via p.risk).
	if p.risk == Unchecked {
		if result := p.platformCheckLibraryInjection(cfg); result.Level == Untrusted {
			p.risk = Untrusted
			p.riskReason = result.Reason
			logger.Debug("[Process.CheckRisk] FAIL library-injection pid=%d reason=%q", p.pid, result.Reason)
			return result
		}

		exe, err := p.getExe()
		if err != nil {
			p.risk = Untrusted
			p.riskReason = "[exe_resolve] " + err.Error()
			logger.Debug("[Process.CheckRisk] FAIL exe-resolve pid=%d err=%v", p.pid, err)
			return RiskResult{Level: Untrusted, Reason: p.riskReason}
		}
		if result := exe.CheckRisk(cfg); result.Level == Untrusted {
			p.risk = Untrusted
			p.riskReason = result.Reason
			return result
		}
		p.risk = Trusted
		logger.Debug("[Process.CheckRisk] one-time PASS pid=%d", p.pid)
	}

	// Phase 3: Ancestor chain check (cached via p.ancestorVerified).
	if cfg.AncestorCheck.Enabled && cfg.MaxAncestorDepth > 0 {
		parent := p.GetParent()
		if parent != nil {
			logger.Debug("[Process.CheckRisk] recurse to parent pid=%d -> ppid=%d depth=%d", p.pid, parent.GetPid(), cfg.MaxAncestorDepth)
			parentCfg := cfg.ForParent()
			parentResult := parent.CheckRisk(parentCfg)
			if parentResult.Level == Untrusted {
				// Do NOT cache Untrusted here — the parent's failure may be transient
				// or specific to a stricter cfg; don't poison the cache.
				return RiskResult{Level: Untrusted, Reason: "untrusted ancestor: " + parentResult.Reason}
			}
		} else {
			logger.Debug("[Process.CheckRisk] no parent (root reached) pid=%d", p.pid)
		}
	}

	p.ancestorVerified = true
	logger.Debug("[Process.CheckRisk] PASS pid=%d (full chain cached)", p.pid)
	return RiskResult{Level: Trusted}
}

// hasTrustedHarnessAncestor walks the ancestor chain looking for a trusted
// harness process. If found, marks the entire chain (from p up to and including
// the harness) as FreeCheck so subsequent CheckRisk calls skip all checks.
func (p *Process) hasTrustedHarnessAncestor(cfg *RiskCheckConfig) bool {
	var chain []*Process
	chain = append(chain, p)

	current := p.GetParent()
	depth := cfg.MaxAncestorDepth
	logger.Debug("[hasTrustedHarnessAncestor] start pid=%d depth=%d trustedHarness=%v", p.pid, depth, cfg.TrustedHarness)
	for current != nil && depth > 0 {
		proc := unwrapProcess(current)
		if proc == nil {
			logger.Debug("[hasTrustedHarnessAncestor] unwrap failed pid=%d parentType=%T", p.pid, current)
			break
		}

		// Short-circuit: ancestor already marked FreeCheck by a prior call.
		if proc.risk == FreeCheck {
			markChainFreeCheck(chain)
			return true
		}

		// Check if this ancestor is a harness (via /proc/<pid>/exe — host real path).
		exePath, err := proc.platformGetExePath()
		if err != nil {
			logger.Debug("[hasTrustedHarnessAncestor] exe resolve failed pid=%d err=%v", proc.pid, err)
		} else {
			logger.Debug("[hasTrustedHarnessAncestor] ancestor pid=%d exe=%s", proc.pid, exePath)
			if isInTrustedHarness(exePath, cfg.TrustedHarness) {
				proc.risk = FreeCheck
				markChainFreeCheck(chain)
				logger.Debug("[hasTrustedHarnessAncestor] found harness pid=%d exe=%s", proc.pid, exePath)
				return true
			}
		}

		chain = append(chain, proc)
		current = proc.GetParent()
		depth--
	}
	logger.Debug("[hasTrustedHarnessAncestor] not found pid=%d (remaining depth=%d, hasParent=%v)", p.pid, depth, current != nil)
	return false
}

func markChainFreeCheck(chain []*Process) {
	for _, proc := range chain {
		proc.risk = FreeCheck
	}
}

// processUnwrapper is implemented by wrapper types (e.g. cache.Process) that
// embed a *Process via the ProcessInf interface.
type processUnwrapper interface {
	UnwrapProcess() *Process
}

// unwrapProcess extracts the underlying *Process from a ProcessInf value,
// handling both direct *Process and wrapper types like cache.Process.
func unwrapProcess(p ProcessInf) *Process {
	if proc, ok := p.(*Process); ok {
		return proc
	}
	if u, ok := p.(processUnwrapper); ok {
		return u.UnwrapProcess()
	}
	return nil
}

func isInTrustedHarness(exePath string, trusted []string) bool {
	for _, t := range trusted {
		if t == exePath {
			return true
		}
	}
	return false
}
