package interpreter

import (
	"strings"

	"github.com/alibaba/CredAgent/internal/osutil"
	"github.com/alibaba/CredAgent/pkg/logger"
)

// Java adds JVM-specific env-var checks: JAVA_TOOL_OPTIONS and _JAVA_OPTIONS
// can both inject JVM arguments (agents, system properties, classpath, etc.)
// without modifying the command line.
//
// For SHA256 measurement, only the "-jar <path>" invocation mode is supported.
// Other modes (-cp, -m, @argfile) cannot reliably determine the entry-point file.
type Java struct {
	Interpreter
}

var javaDangerousEnvPrefixes = []string{"JAVA_TOOL_OPTIONS=", "_JAVA_OPTIONS="}

var javaDangerousArgPrefixes = []string{
	"-javaagent:",
	"-agentpath:",
	"-agentlib:",
}

// javaSkipNextFlags are JVM flags that consume the next argument as a value.
var javaSkipNextFlags = map[string]bool{
	"-cp": true, "-classpath": true, "--class-path": true,
	"--module-path": true, "-p": true,
	"--add-modules": true, "--add-exports": true, "--add-opens": true, "--add-reads": true,
	"--patch-module": true,
	"-d": true, "-encoding": true, "-source": true, "-target": true,
}

func (j *Java) extractScriptPath(args []string) (string, bool) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-jar" {
			if i+1 < len(args) {
				return args[i+1], false
			}
			return "", false
		}
		// -cp / -classpath with main class name → can't determine entry file
		if javaSkipNextFlags[arg] {
			i++
			continue
		}
		// JVM options starting with - (e.g. -Xmx512m, -Dprop=val, --module-path)
		if strings.HasPrefix(arg, "-") {
			continue
		}
		// Bare class name (e.g. "com.example.Main") → can't determine entry file
		return "", false
	}
	return "", false
}

func (j *Java) GetSha256() (string, error) {
	return j.getScriptSha256(j)
}

func (j *Java) CheckRisk(cfg *osutil.RiskCheckConfig) osutil.RiskResult {
	if r := j.Interpreter.CheckRisk(cfg); r.Level == osutil.Untrusted {
		return r
	}
	opts := resolveOpts(cfg, "java")
	if !opts.Enabled {
		return osutil.RiskResult{Level: osutil.Trusted}
	}
	if r := j.checkDangerousEnv("java", javaDangerousEnvPrefixes, opts.TrustedEnv); r.Level == osutil.Untrusted {
		return r
	}
	if r := j.checkDangerousArgs("java", nil, javaDangerousArgPrefixes); r.Level == osutil.Untrusted {
		logger.Debug("[Java.CheckRisk] FAIL dangerous-args pid=%d reason=%q", j.GetPid(), r.Reason)
		return r
	}

	if r := j.checkScriptTrust("java", j, cfg); r.Level == osutil.Untrusted {
		logger.Debug("[Java.CheckRisk] FAIL script-trust pid=%d reason=%q", j.GetPid(), r.Reason)
		return r
	}

	return osutil.RiskResult{Level: osutil.Trusted}
}
