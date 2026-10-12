// Package interpreter implements interpreter-family-specific risk checks
// on top of osutil.Binary's generic checks.
//
// Structure:
//
//	Binary (osutil)                     - generic binary checks (path, native env)
//	Interpreter (this file)             - base, just inherits Binary; provides
//	                                       helpers + path/factory dispatch
//	Python (python.go)                  - PYTHONPATH/.pth/sitecustomize
//	Node, Ruby, Perl, Java,             - per-family env-var checks
//	PHP (own file)
//
// Note: bash/sh are NOT interpreter types — they are treated as plain
// binaries because bash is never authorized to access credentials directly;
// only child processes (fork+exec) access credentials and are independently
// checked. Interpreter-specific checks on bash (BASH_ENV, --init-file,
// script trust) provide no real security benefit and cause false positives.
//
// Each family-specific type extends Interpreter (via Go embedding) and
// overrides CheckRisk to add its own checks on top of the inherited ones.
// New interpreters are added by creating a new file with a new type — no
// changes to existing files needed beyond registering the factory case.
package interpreter

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/aliyun/credagent/internal/osutil"
	"github.com/aliyun/credagent/pkg/logger"
)

// ScriptExtractor extracts the main script path from command-line arguments.
// Each interpreter family implements this to handle its own argument conventions.
type ScriptExtractor interface {
	// extractScriptPath parses args (excluding argv[0]) and returns:
	//   scriptPath  — absolute or relative path of the main script file
	//   inlineExec  — true if the interpreter is running inline code (-c, -e, etc.)
	// When both are empty/false, no script file was identified (fail-closed → Untrusted).
	extractScriptPath(args []string) (scriptPath string, inlineExec bool)
}

// Config holds interpreter-related configuration.
type Config struct {
	// TrustedPaths maps interpreter family to list of trusted full paths.
	// e.g. {"python": ["/usr/bin/python3", "/usr/bin/python3.12"]}
	TrustedPaths map[string][]string
}

var globalConfig *Config

// SetConfig sets the global interpreter configuration.
func SetConfig(cfg *Config) {
	globalConfig = cfg
}

// Interpreter is the base type for all interpreter binaries. It embeds
// *osutil.Binary so all generic binary checks are inherited automatically.
// Family-specific types (Python, Node, Ruby, …) embed Interpreter and add
// their own checks via Go method shadowing.
type Interpreter struct {
	*osutil.Binary
}

// CheckRisk is the base interpreter check — just the embedded Binary's checks.
// Family-specific subtypes override this to add more checks after calling
// i.Interpreter.CheckRisk(cfg) for the inherited behavior.
func (i *Interpreter) CheckRisk(cfg *osutil.RiskCheckConfig) osutil.RiskResult {
	logger.Debug("[Interpreter.CheckRisk] pid=%d path=%s", i.GetPid(), i.GetPath())
	return i.Binary.CheckRisk(cfg)
}

// getCmdlineArgs returns the command-line arguments of this interpreter's
// process. Prioritizes the CmdlineProvider (which queries eBPF and auditd
// sources in config order — both capture cmdline at execve time and are
// tamper-proof) over /proc/<pid>/cmdline (spoofable after startup).
func (i *Interpreter) getCmdlineArgs() ([]string, error) {
	if provider := osutil.GetCmdlineProvider(); provider != nil {
		if cmd, ok := provider.Lookup(uint32(i.GetPid())); ok && cmd != "" {
			return strings.Split(cmd, " "), nil
		}
	}
	return osutil.ReadProcCmdlineArgs(i.GetPid())
}

// resolveScript extracts the main script path from cmdline using the
// family-specific extractor, resolves relative paths, and returns the
// absolute script path. Returns an error for inline exec, stdin, or
// when the script path cannot be determined.
func (i *Interpreter) resolveScript(extractor ScriptExtractor) (string, error) {
	args, err := i.getCmdlineArgs()
	if err != nil {
		return "", fmt.Errorf("cannot read cmdline: %w", err)
	}
	if len(args) <= 1 {
		return "", fmt.Errorf("no script argument (interactive/stdin mode)")
	}

	scriptPath, inlineExec := extractor.extractScriptPath(args[1:])
	if inlineExec {
		return "", fmt.Errorf("inline code execution")
	}
	if scriptPath == "" {
		return "", fmt.Errorf("cannot identify script path from cmdline")
	}
	if scriptPath == "-" {
		return "", fmt.Errorf("reading from stdin")
	}

	if !filepath.IsAbs(scriptPath) {
		cwd, err := osutil.ReadProcCwd(i.GetPid())
		if err != nil {
			return "", fmt.Errorf("cannot resolve relative script path %q: %w", scriptPath, err)
		}
		scriptPath = filepath.Join(cwd, scriptPath)
	}
	return scriptPath, nil
}

// checkScriptTrust identifies the main script file via resolveScript, then
// verifies it is in a trusted location with safe ownership/permissions.
// If the script cannot be determined (interactive, inline, stdin), returns Untrusted.
func (i *Interpreter) checkScriptTrust(family string, extractor ScriptExtractor, cfg *osutil.RiskCheckConfig) osutil.RiskResult {
	opts := resolveOpts(cfg, family)

	scriptPath, err := i.resolveScript(extractor)
	if err != nil {
		reason := fmt.Sprintf("[script_trust_check.%s] %s", family, err.Error())
		logger.Debug("[checkScriptTrust] FAIL pid=%d reason=%q", i.GetPid(), reason)
		return osutil.RiskResult{Level: osutil.Untrusted, Reason: reason}
	}

	logger.Debug("[checkScriptTrust] pid=%d family=%s script=%s", i.GetPid(), family, scriptPath)

	trustedScripts := opts.TrustedScripts
	if cfg != nil && len(cfg.BinaryCheck.TrustedPrograms) > 0 {
		merged := make([]string, 0, len(trustedScripts)+len(cfg.BinaryCheck.TrustedPrograms))
		merged = append(merged, trustedScripts...)
		merged = append(merged, cfg.BinaryCheck.TrustedPrograms...)
		trustedScripts = merged
	}
	// Use resolved host path for policy matching (TrustedPrograms comparison),
	// and /proc/<pid>/root path for filesystem ownership checks.
	resolvedPath := osutil.ResolveNamespacePath(i.GetPid(), scriptPath)
	ioPath := osutil.ProcRootPath(i.GetPid(), scriptPath)
	return osutil.CheckScriptPathTrust(resolvedPath, ioPath, trustedScripts)
}

// getScriptSha256 computes the SHA256 hash of the main script file (not the
// interpreter binary). Used by family subtypes to override GetSha256().
func (i *Interpreter) getScriptSha256(extractor ScriptExtractor) (string, error) {
	scriptPath, err := i.resolveScript(extractor)
	if err != nil {
		return "", fmt.Errorf("cannot determine script for SHA256: %w", err)
	}
	ioPath := osutil.ProcRootPath(i.GetPid(), scriptPath)
	return osutil.GetExeSHA256Func(ioPath)
}

// checkDangerousEnv is a helper available to all family subtypes. It reads
// the process environ and returns Untrusted on the first env var whose
// prefix matches `prefixes` and whose value is not in `trustedEnv[name]`.
func (i *Interpreter) checkDangerousEnv(family string, prefixes []string, trustedEnv map[string][]string) osutil.RiskResult {
	envVars, err := osutil.ReadProcEnviron(i.GetPid())
	if err != nil {
		logger.Debug("checkDangerousEnv(%d): cannot read environ: %v", i.GetPid(), err)
		return osutil.RiskResult{Level: osutil.Trusted}
	}
	for _, envVar := range envVars {
		if envVar == "" {
			continue
		}
		for _, prefix := range prefixes {
			if !strings.HasPrefix(envVar, prefix) {
				continue
			}
			if osutil.IsEnvVarTrusted(envVar, prefix, trustedEnv) {
				continue
			}
			return osutil.RiskResult{
				Level:  osutil.Untrusted,
				Reason: fmt.Sprintf("[interpreter_check.%s] dangerous environment variable: %s", family, envVar),
			}
		}
	}
	return osutil.RiskResult{Level: osutil.Trusted}
}

// checkDangerousArgs reads the process cmdline and returns Untrusted if any
// argument matches an exact dangerous flag or a dangerous prefix. Used by
// family subtypes to detect code-injection arguments (e.g. --require, -javaagent:).
func (i *Interpreter) checkDangerousArgs(family string, exactFlags []string, prefixes []string) osutil.RiskResult {
	args, err := i.getCmdlineArgs()
	if err != nil {
		logger.Debug("checkDangerousArgs(%d): cannot read cmdline: %v", i.GetPid(), err)
		return osutil.RiskResult{Level: osutil.Trusted}
	}
	if len(args) <= 1 {
		return osutil.RiskResult{Level: osutil.Trusted}
	}
	for _, arg := range args[1:] {
		for _, flag := range exactFlags {
			if arg == flag {
				return osutil.RiskResult{
					Level:  osutil.Untrusted,
					Reason: fmt.Sprintf("[dangerous_args_check.%s] dangerous argument: %s", family, arg),
				}
			}
		}
		for _, pfx := range prefixes {
			if strings.HasPrefix(arg, pfx) {
				return osutil.RiskResult{
					Level:  osutil.Untrusted,
					Reason: fmt.Sprintf("[dangerous_args_check.%s] dangerous argument: %s", family, arg),
				}
			}
		}
	}
	return osutil.RiskResult{Level: osutil.Trusted}
}

// resolveOpts returns this family's options from cfg, defaulting to Enabled=true.
func resolveOpts(cfg *osutil.RiskCheckConfig, family string) osutil.InterpreterCheckOpts {
	if cfg == nil || cfg.InterpreterCheck == nil {
		return osutil.InterpreterCheckOpts{Enabled: true}
	}
	opts, ok := cfg.InterpreterCheck[family]
	if !ok {
		return osutil.InterpreterCheckOpts{Enabled: true}
	}
	return opts
}

// NewInterpreter is the package factory. Returns:
//   - nil if basename doesn't look like an interpreter, OR path isn't valid;
//     callers (NewBinary) then fall back to plain Binary handling.
//   - a family-specific concrete type otherwise (e.g. *Python, *Node, ...).
//
// Matching priority:
//  1. Built-in matchFamily (exact names + version regex) + isValidInterpreterPath
//  2. Configured exe_paths (via globalConfig.TrustedPaths) — full path exact match
func NewInterpreter(exePath string, pid int32) osutil.BinaryInf {
	family := matchFamily(filepath.Base(exePath))
	if family != "" && isValidInterpreterPath(exePath, family) {
		return newInterpreterByFamily(family, exePath, pid)
	}

	if family = matchFamilyByExePaths(exePath); family != "" {
		return newInterpreterByFamily(family, exePath, pid)
	}

	return nil
}

func newInterpreterByFamily(family, exePath string, pid int32) osutil.BinaryInf {
	base := Interpreter{Binary: osutil.NewBinaryStruct(exePath, pid)}
	switch family {
	case "python":
		return &Python{Interpreter: base}
	case "node":
		return &Node{Interpreter: base}
	case "ruby":
		return &Ruby{Interpreter: base}
	case "perl":
		return &Perl{Interpreter: base}
	case "java":
		return &Java{Interpreter: base}
	case "php":
		return &PHP{Interpreter: base}
	}
	return &base
}

// matchFamilyByExePaths checks if exePath is explicitly listed in any
// family's TrustedPaths (populated from config exe_paths). Returns the
// family name on match, empty string otherwise.
func matchFamilyByExePaths(exePath string) string {
	if globalConfig == nil {
		return ""
	}
	for family, paths := range globalConfig.TrustedPaths {
		for _, p := range paths {
			if p == exePath {
				return family
			}
		}
	}
	return ""
}

type familyMatcher struct {
	names        []string
	versionRegex *regexp.Regexp
}

var familyMatchers = []struct {
	family  string
	matcher familyMatcher
}{
	{"python", familyMatcher{
		names:        []string{"python", "python2", "python3"},
		versionRegex: regexp.MustCompile(`^python\d[\d.]*$`),
	}},
	{"node", familyMatcher{
		names: []string{"node", "nodejs"},
	}},
	{"ruby", familyMatcher{
		names:        []string{"ruby"},
		versionRegex: regexp.MustCompile(`^ruby\d[\d.]*$`),
	}},
	{"perl", familyMatcher{
		names:        []string{"perl"},
		versionRegex: regexp.MustCompile(`^perl\d[\d.]*$`),
	}},
	{"java", familyMatcher{
		names: []string{"java"},
	}},

	{"php", familyMatcher{
		names:        []string{"php", "php-fpm"},
		versionRegex: regexp.MustCompile(`^php\d[\d.]*$`),
	}},
}

// matchFamily returns the interpreter family if baseName matches a known
// interpreter name or versioned variant (e.g. python3.12, php8.1).
// Uses exact name matching + version suffix regex to avoid false positives
// on tools like pythonista, perldoc, phpstorm.
func matchFamily(baseName string) string {
	lower := strings.ToLower(baseName)
	for _, entry := range familyMatchers {
		for _, name := range entry.matcher.names {
			if lower == name {
				return entry.family
			}
		}
		if entry.matcher.versionRegex != nil && entry.matcher.versionRegex.MatchString(lower) {
			return entry.family
		}
	}
	return ""
}

// isValidInterpreterPath checks if the interpreter path is in a recognized
// interpreter location: in the daemon's system PATH, or in the global
// interpreter config's TrustedPaths[family].
func isValidInterpreterPath(path, family string) bool {
	dir := filepath.Dir(path)

	if osutil.IsInSystemPATH(dir) {
		return true
	}

	if globalConfig != nil {
		if trustedPaths, ok := globalConfig.TrustedPaths[family]; ok {
			for _, tp := range trustedPaths {
				if tp == path {
					return true
				}
			}
		}
	}

	return false
}

// Register registers the interpreter factory with osutil at init time.
func Register() {
	osutil.SetInterpreterFactory(NewInterpreter)
}
