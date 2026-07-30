package interpreter

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/alibaba/CredAgent/internal/osutil"
	"github.com/alibaba/CredAgent/pkg/logger"
)

// Python adds python-specific checks on top of the base Interpreter:
//   - dangerous PYTHON* env vars (PYTHONPATH, PYTHONUSERBASE, etc.)
//   - unknown / non-safelist PYTHON* env vars
//   - .pth file injection in user site-packages
//   - sitecustomize.py / usercustomize.py injection
type Python struct {
	Interpreter
}

// pythonDangerousEnvPrefixes are env vars that can divert python's import
// or startup behavior — any of these in a process's environ is suspicious.
var pythonDangerousEnvPrefixes = []string{
	"PYTHONPATH=",
	"PYTHONSTARTUP=",
	"PYTHONHOME=",
	"PYTHONINSPECT=",
	"PYTHONUSERBASE=",
	"VIRTUAL_ENV=",
}

// pythonSafeEnvPrefixes lists known-benign PYTHON* vars that don't affect
// code loading. Anything else starting with "PYTHON" is treated as suspicious.
var pythonSafeEnvPrefixes = []string{
	"PYTHONDONTWRITEBYTECODE=", "PYTHONUNBUFFERED=", "PYTHONHASHSEED=",
	"PYTHONIOENCODING=", "PYTHONWARNINGS=", "PYTHONFAULTHANDLER=",
	"PYTHONCOERCECLOCALE=", "PYTHONLEGACYWINDOWSSTDIO=", "PYTHONNOUSERSITE=",
	"PYTHONOPTIMIZE=", "PYTHONUTF8=", "PYTHONDEBUG=", "PYTHONVERBOSE=",
	"PYTHONTRACEMALLOC=", "PYTHONPROFILEIMPORTTIME=", "PYTHONDEVMODE=",
	"PYTHONMALLOC=", "PYTHONBREAKPOINT=", "PYTHONPYCACHEPREFIX=",
	"PYTHONSAFEPATH=", "PYTHONWARNDEFAULTENCODING=", "PYTHONINTMAXSTRDIGITS=",
}

// pythonInlineFlags are flags that indicate inline/non-file execution.
var pythonInlineFlags = map[string]bool{
	"-c": true,
	"-m": true,
}

// pythonDangerousArgs are arguments that alter execution mode in a way that
// opens the process to manipulation (e.g. -i keeps interactive prompt alive).
var pythonDangerousArgs = []string{"-i"}

// pythonSkipNextFlags are flags that consume the next argument as a value.
var pythonSkipNextFlags = map[string]bool{
	"-W": true, "-X": true, "-Q": true,
}

func (p *Python) extractScriptPath(args []string) (string, bool) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			if i+1 < len(args) {
				return args[i+1], false
			}
			return "", false
		}
		if arg == "-" {
			return "-", false
		}
		if pythonInlineFlags[arg] {
			return "", true
		}
		if pythonSkipNextFlags[arg] {
			i++
			continue
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		return arg, false
	}
	return "", false
}

func (p *Python) GetSha256() (string, error) {
	return p.getScriptSha256(p)
}

func (p *Python) CheckRisk(cfg *osutil.RiskCheckConfig) osutil.RiskResult {
	logger.Debug("[Python.CheckRisk] pid=%d path=%s", p.GetPid(), p.GetPath())

	if r := p.Interpreter.CheckRisk(cfg); r.Level == osutil.Untrusted {
		return r
	}

	opts := resolveOpts(cfg, "python")

	envVars, err := osutil.ReadProcEnviron(p.GetPid())
	if err != nil {
		logger.Debug("[Python.CheckRisk] cannot read environ pid=%d: %v", p.GetPid(), err)
		return osutil.RiskResult{Level: osutil.Trusted}
	}

	// 1. Explicit dangerous env vars (always checked, cannot be disabled)
	if r := p.scanDangerousEnv(envVars, opts.TrustedEnv); r.Level == osutil.Untrusted {
		logger.Debug("[Python.CheckRisk] FAIL danger-env pid=%d reason=%q", p.GetPid(), r.Reason)
		return r
	}

	// 2. Unknown PYTHON* env vars (always checked, cannot be disabled)
	if r := p.scanUnknownPythonVars(envVars); r.Level == osutil.Untrusted {
		logger.Debug("[Python.CheckRisk] FAIL unknown-PYTHON-var pid=%d reason=%q", p.GetPid(), r.Reason)
		return r
	}

	// 3. Dangerous arguments (always checked, cannot be disabled)
	if r := p.checkDangerousArgs("python", pythonDangerousArgs, nil); r.Level == osutil.Untrusted {
		logger.Debug("[Python.CheckRisk] FAIL dangerous-args pid=%d reason=%q", p.GetPid(), r.Reason)
		return r
	}

	// Checks 4 & 5 are filesystem-level checks, gated by the enabled toggle.
	if !opts.Enabled {
		logger.Debug("[Python.CheckRisk] PASS pid=%d (filesystem checks disabled)", p.GetPid())
		return osutil.RiskResult{Level: osutil.Trusted}
	}

	// 4. .pth / sitecustomize / usercustomize injection
	homeDir := osutil.GetEnvValueFromList(envVars, "HOME")
	if r := checkPthInjection(p.GetPid(), p.GetPath(), homeDir); r.Level == osutil.Untrusted {
		logger.Debug("[Python.CheckRisk] FAIL pth/sitecustomize pid=%d reason=%q", p.GetPid(), r.Reason)
		return r
	}

	// 5. Script trust check
	if r := p.checkScriptTrust("python", p, cfg); r.Level == osutil.Untrusted {
		logger.Debug("[Python.CheckRisk] FAIL script-trust pid=%d reason=%q", p.GetPid(), r.Reason)
		return r
	}

	logger.Debug("[Python.CheckRisk] PASS pid=%d", p.GetPid())
	return osutil.RiskResult{Level: osutil.Trusted}
}

func (p *Python) scanDangerousEnv(envVars []string, trustedEnv map[string][]string) osutil.RiskResult {
	for _, envVar := range envVars {
		if envVar == "" {
			continue
		}
		for _, prefix := range pythonDangerousEnvPrefixes {
			if !strings.HasPrefix(envVar, prefix) {
				continue
			}
			if osutil.IsEnvVarTrusted(envVar, prefix, trustedEnv) {
				continue
			}
			return osutil.RiskResult{
				Level:  osutil.Untrusted,
				Reason: fmt.Sprintf("[interpreter_check.python] dangerous environment variable: %s", envVar),
			}
		}
	}
	return osutil.RiskResult{Level: osutil.Trusted}
}

func (p *Python) scanUnknownPythonVars(envVars []string) osutil.RiskResult {
	for _, envVar := range envVars {
		if !strings.HasPrefix(envVar, "PYTHON") {
			continue
		}
		if isPythonEnvSafe(envVar) {
			continue
		}
		// Already-reported dangerous prefixes were caught above; this catches
		// any PYTHON* var not in either list.
		if isDangerousPythonPrefix(envVar) {
			continue
		}
		return osutil.RiskResult{
			Level:  osutil.Untrusted,
			Reason: fmt.Sprintf("[interpreter_check.python] unknown Python environment variable: %s", envVar),
		}
	}
	return osutil.RiskResult{Level: osutil.Trusted}
}

func isPythonEnvSafe(envVar string) bool {
	for _, safe := range pythonSafeEnvPrefixes {
		if strings.HasPrefix(envVar, safe) {
			return true
		}
	}
	return false
}

func isDangerousPythonPrefix(envVar string) bool {
	for _, p := range pythonDangerousEnvPrefixes {
		if strings.HasPrefix(envVar, p) {
			return true
		}
	}
	return false
}

// --- .pth file / sitecustomize / usercustomize injection ---

// checkPthInjection inspects the user site-packages dir for mutable injection files:
//   - any *.pth file (Python silently executes "import X" lines in .pth files
//     during interpreter startup, an attractive injection target);
//   - sitecustomize.py / usercustomize.py (Python auto-imports these at startup).
//
// Only user site-packages (~/.local/lib/pythonX.Y/site-packages/) is checked.
// System site-packages is assumed safe (root-owned, managed by package manager).
// Files with the immutable attribute (chattr +i) are considered protected.
func checkPthInjection(pid int32, exePath, homeDir string) osutil.RiskResult {
	version := extractPythonVersion(exePath)
	if version == "" {
		return osutil.RiskResult{Level: osutil.Trusted}
	}

	if homeDir == "" {
		return osutil.RiskResult{Level: osutil.Trusted}
	}

	userSiteDir := filepath.Join(homeDir, ".local", "lib", "python"+version, "site-packages")
	hostSiteDir := osutil.ProcRootPath(pid, userSiteDir)

	if r := scanDirForPth(hostSiteDir); r.Level == osutil.Untrusted {
		return r
	}
	if r := scanDirForCustomize(hostSiteDir); r.Level == osutil.Untrusted {
		return r
	}

	return osutil.RiskResult{Level: osutil.Trusted}
}

func extractPythonVersion(exePath string) string {
	base := filepath.Base(exePath)
	if !strings.HasPrefix(base, "python") {
		return ""
	}
	rest := base[len("python"):]
	if rest == "" || rest[0] < '0' || rest[0] > '9' {
		return ""
	}
	// Accept "3", "3.12", "3.12.1" etc.
	dotIdx := strings.IndexByte(rest, '.')
	if dotIdx < 0 {
		return rest
	}
	end := dotIdx + 1
	for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
		end++
	}
	return rest[:end]
}


func scanDirForPth(dir string) osutil.RiskResult {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return osutil.RiskResult{Level: osutil.Trusted}
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".pth") {
			continue
		}
		pthPath := filepath.Join(dir, entry.Name())
		if isImmutable(pthPath) {
			continue
		}
		return osutil.RiskResult{
			Level:  osutil.Untrusted,
			Reason: fmt.Sprintf("[interpreter_check.python] mutable .pth file in user site-packages: %s", pthPath),
		}
	}
	return osutil.RiskResult{Level: osutil.Trusted}
}

func scanDirForCustomize(dir string) osutil.RiskResult {
	for _, name := range []string{"sitecustomize.py", "usercustomize.py"} {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err != nil {
			continue
		}
		if isImmutable(path) {
			continue
		}
		return osutil.RiskResult{
			Level:  osutil.Untrusted,
			Reason: fmt.Sprintf("[interpreter_check.python] mutable %s in user site-packages: %s", name, path),
		}
	}
	return osutil.RiskResult{Level: osutil.Trusted}
}
