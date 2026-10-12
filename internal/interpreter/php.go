package interpreter

import (
	"strings"

	"github.com/aliyun/credagent/internal/osutil"
	"github.com/aliyun/credagent/pkg/logger"
)

// PHP adds PHP-specific env-var checks: PHPRC (custom php.ini location),
// PHP_INI_SCAN_DIR (extra ini scan directory).
type PHP struct {
	Interpreter
}

var phpDangerousEnvPrefixes = []string{"PHPRC=", "PHP_INI_SCAN_DIR="}

var phpDangerousDirectives = []string{
	"auto_prepend_file=",
	"auto_append_file=",
	"extension=",
}

func (p *PHP) extractScriptPath(args []string) (string, bool) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			if i+1 < len(args) {
				return args[i+1], false
			}
			return "", false
		}
		if arg == "-r" {
			return "", true
		}
		if arg == "-d" || arg == "-c" || arg == "-z" {
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

func (p *PHP) GetSha256() (string, error) {
	return p.getScriptSha256(p)
}

func (p *PHP) CheckRisk(cfg *osutil.RiskCheckConfig) osutil.RiskResult {
	if r := p.Interpreter.CheckRisk(cfg); r.Level == osutil.Untrusted {
		return r
	}
	opts := resolveOpts(cfg, "php")
	if !opts.Enabled {
		return osutil.RiskResult{Level: osutil.Trusted}
	}
	if r := p.checkDangerousEnv("php", phpDangerousEnvPrefixes, opts.TrustedEnv); r.Level == osutil.Untrusted {
		return r
	}
	if r := p.checkPhpDangerousArgs(); r.Level == osutil.Untrusted {
		logger.Debug("[PHP.CheckRisk] FAIL dangerous-args pid=%d reason=%q", p.GetPid(), r.Reason)
		return r
	}

	if r := p.checkScriptTrust("php", p, cfg); r.Level == osutil.Untrusted {
		logger.Debug("[PHP.CheckRisk] FAIL script-trust pid=%d reason=%q", p.GetPid(), r.Reason)
		return r
	}

	return osutil.RiskResult{Level: osutil.Trusted}
}

// checkPhpDangerousArgs checks for -z (load Zend extension) and -d with
// dangerous directives. Handles both "-d directive=val" (space) and
// "-ddirective=val" (no space) syntaxes.
func (p *PHP) checkPhpDangerousArgs() osutil.RiskResult {
	args, err := p.getCmdlineArgs()
	if err != nil {
		return osutil.RiskResult{Level: osutil.Trusted}
	}
	for i := 1; i < len(args); i++ {
		arg := args[i]
		if arg == "-z" {
			return osutil.RiskResult{
				Level:  osutil.Untrusted,
				Reason: "[dangerous_args_check.php] dangerous argument: -z (Zend extension loading)",
			}
		}
		var directive string
		if arg == "-d" && i+1 < len(args) {
			directive = args[i+1]
			i++
		} else if strings.HasPrefix(arg, "-d") && len(arg) > 2 {
			directive = arg[2:]
		}
		if directive != "" {
			for _, dp := range phpDangerousDirectives {
				if strings.HasPrefix(directive, dp) {
					return osutil.RiskResult{
						Level:  osutil.Untrusted,
						Reason: "[dangerous_args_check.php] dangerous directive: -d " + directive,
					}
				}
			}
		}
	}
	return osutil.RiskResult{Level: osutil.Trusted}
}
