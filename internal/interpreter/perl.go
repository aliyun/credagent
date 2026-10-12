package interpreter

import (
	"strings"

	"github.com/aliyun/credagent/internal/osutil"
	"github.com/aliyun/credagent/pkg/logger"
)

// Perl adds Perl-specific env-var checks: PERL5OPT (extra perl options),
// PERL5LIB / PERLLIB (extra @INC paths).
type Perl struct {
	Interpreter
}

var perlDangerousEnvPrefixes = []string{"PERL5OPT=", "PERL5LIB=", "PERLLIB="}

var perlDangerousArgs = []string{"-M", "-m"}

func (p *Perl) extractScriptPath(args []string) (string, bool) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			if i+1 < len(args) {
				return args[i+1], false
			}
			return "", false
		}
		if arg == "-e" || arg == "-E" {
			return "", true
		}
		if arg == "-I" || arg == "-M" || arg == "-m" {
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

func (p *Perl) GetSha256() (string, error) {
	return p.getScriptSha256(p)
}

func (p *Perl) CheckRisk(cfg *osutil.RiskCheckConfig) osutil.RiskResult {
	if r := p.Interpreter.CheckRisk(cfg); r.Level == osutil.Untrusted {
		return r
	}
	opts := resolveOpts(cfg, "perl")
	if !opts.Enabled {
		return osutil.RiskResult{Level: osutil.Trusted}
	}
	if r := p.checkDangerousEnv("perl", perlDangerousEnvPrefixes, opts.TrustedEnv); r.Level == osutil.Untrusted {
		return r
	}
	if r := p.checkDangerousArgs("perl", perlDangerousArgs, nil); r.Level == osutil.Untrusted {
		logger.Debug("[Perl.CheckRisk] FAIL dangerous-args pid=%d reason=%q", p.GetPid(), r.Reason)
		return r
	}

	if r := p.checkScriptTrust("perl", p, cfg); r.Level == osutil.Untrusted {
		logger.Debug("[Perl.CheckRisk] FAIL script-trust pid=%d reason=%q", p.GetPid(), r.Reason)
		return r
	}

	return osutil.RiskResult{Level: osutil.Trusted}
}
