package osutil

import (
	"strings"
)

// SecurityCheckConfig holds all security check options passed from the config layer.
// Kept for backward compatibility; new code should use RiskCheckConfig.
type SecurityCheckConfig = RiskCheckConfig

// SecurityCheckResult holds the result of process security verification.
// Kept for backward compatibility; new code should use RiskResult.
type SecurityCheckResult struct {
	Denied bool
	Reason string
}

// BinaryCheckOpts controls the binary trust check (path safety, ownership).
// Used by Binary.CheckRisk for both the requesting process and its ancestors.
type BinaryCheckOpts struct {
	Enabled         bool
	TrustedPrograms []string // explicitly trusted binary paths (bypasses strict checks)
}

// ProcessStatusCheckOpts controls the process status (tracePid/seccomp) check.
type ProcessStatusCheckOpts struct {
	Enabled bool
}

// LibraryInjectionCheckOpts controls the library injection check.
type LibraryInjectionCheckOpts struct {
	Enabled         bool
	TrustedLibPaths []string
}

// EnvVarCheckOpts controls the native environment variable check
// (LD_PRELOAD, LD_LIBRARY_PATH, LD_AUDIT, DYLD_INSERT_LIBRARIES).
type EnvVarCheckOpts struct {
	Enabled    bool
	TrustedEnv map[string][]string
}

// InterpreterCheckOpts controls interpreter-specific security checks.
// Consumed by the interpreter package, indexed by family ("python", "node", ...).
type InterpreterCheckOpts struct {
	Enabled        bool
	TrustedEnv     map[string][]string
	TrustedScripts []string
	ExePaths       []string
}

// AncestorCheckOpts controls whether the ancestor chain is verified at all.
type AncestorCheckOpts struct {
	Enabled bool
}

// --- Native env check (LD_PRELOAD, DYLD_INSERT_LIBRARIES, etc.) ---
// Used by Binary.CheckRisk via Binary.checkNativeEnv. Applies to every
// binary, not just interpreters.

func checkNativeEnvRisk(envVars []string, trustedEnv map[string][]string) RiskResult {
	for _, envVar := range envVars {
		if envVar == "" {
			continue
		}
		for _, prefix := range getNativeDangerousPrefixes() {
			if !strings.HasPrefix(envVar, prefix) {
				continue
			}
			if isEnvVarTrusted(envVar, prefix, trustedEnv) {
				continue
			}
			return RiskResult{
				Level:  Untrusted,
				Reason: "[env_var_check] dangerous environment variable: " + envVar,
			}
		}
	}
	return RiskResult{Level: Trusted}
}

// IsEnvVarTrusted is the exported wrapper used by interpreter family types.
func IsEnvVarTrusted(envVar string, prefix string, trustedEnv map[string][]string) bool {
	return isEnvVarTrusted(envVar, prefix, trustedEnv)
}

// isEnvVarTrusted checks if a specific env var value is in the trusted list.
func isEnvVarTrusted(envVar string, prefix string, trustedEnv map[string][]string) bool {
	if trustedEnv == nil {
		return false
	}
	varName := strings.TrimSuffix(prefix, "=")
	trustedValues, exists := trustedEnv[varName]
	if !exists {
		return false
	}
	value := envVar[len(prefix):]
	for _, tv := range trustedValues {
		if tv == value {
			return true
		}
	}
	return false
}

// GetEnvValueFromList extracts the value of `name` from a list of "KEY=VALUE" strings.
// Exported for use by the interpreter package.
func GetEnvValueFromList(envVars []string, name string) string {
	prefix := name + "="
	for _, envVar := range envVars {
		if strings.HasPrefix(envVar, prefix) {
			return envVar[len(prefix):]
		}
	}
	return ""
}
