package interpreter

import (
	"strings"

	"github.com/alibaba/CredAgent/internal/osutil"
	"github.com/alibaba/CredAgent/pkg/logger"
)

// Ruby adds Ruby-specific env-var checks: RUBYOPT (extra -r requires),
// RUBYLIB (extra load path).
type Ruby struct {
	Interpreter
}

var rubyDangerousEnvPrefixes = []string{"RUBYOPT=", "RUBYLIB="}

var rubyDangerousArgs = []string{"-r"}

func (rb *Ruby) extractScriptPath(args []string) (string, bool) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			if i+1 < len(args) {
				return args[i+1], false
			}
			return "", false
		}
		if arg == "-e" {
			return "", true
		}
		if arg == "-r" || arg == "-I" {
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

func (rb *Ruby) GetSha256() (string, error) {
	return rb.getScriptSha256(rb)
}

func (rb *Ruby) CheckRisk(cfg *osutil.RiskCheckConfig) osutil.RiskResult {
	if rr := rb.Interpreter.CheckRisk(cfg); rr.Level == osutil.Untrusted {
		return rr
	}
	opts := resolveOpts(cfg, "ruby")
	if !opts.Enabled {
		return osutil.RiskResult{Level: osutil.Trusted}
	}
	if rr := rb.checkDangerousEnv("ruby", rubyDangerousEnvPrefixes, opts.TrustedEnv); rr.Level == osutil.Untrusted {
		return rr
	}
	if rr := rb.checkDangerousArgs("ruby", rubyDangerousArgs, nil); rr.Level == osutil.Untrusted {
		logger.Debug("[Ruby.CheckRisk] FAIL dangerous-args pid=%d reason=%q", rb.GetPid(), rr.Reason)
		return rr
	}

	if rr := rb.checkScriptTrust("ruby", rb, cfg); rr.Level == osutil.Untrusted {
		logger.Debug("[Ruby.CheckRisk] FAIL script-trust pid=%d reason=%q", rb.GetPid(), rr.Reason)
		return rr
	}

	return osutil.RiskResult{Level: osutil.Trusted}
}
