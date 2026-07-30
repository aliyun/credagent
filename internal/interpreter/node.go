package interpreter

import (
	"strings"

	"github.com/alibaba/CredAgent/internal/osutil"
	"github.com/alibaba/CredAgent/pkg/logger"
)

// Node adds Node.js-specific env-var checks: NODE_OPTIONS (can inject require'd
// modules) and NODE_PATH (extra module resolution path).
type Node struct {
	Interpreter
}

var nodeDangerousEnvPrefixes = []string{"NODE_OPTIONS=", "NODE_PATH="}

var nodeDangerousArgs = []string{
	"--require", "-r",
	"--loader", "--experimental-loader",
	"--import",
}

// nodeSkipNextFlags are flags that consume the next argument as a value.
var nodeSkipNextFlags = map[string]bool{
	"-r": true, "--require": true, "--loader": true,
	"--experimental-loader": true, "--import": true,
}

func (n *Node) extractScriptPath(args []string) (string, bool) {
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
		if arg == "-e" || arg == "--eval" || arg == "-p" || arg == "--print" {
			return "", true
		}
		if nodeSkipNextFlags[arg] {
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

func (n *Node) GetSha256() (string, error) {
	return n.getScriptSha256(n)
}

func (n *Node) CheckRisk(cfg *osutil.RiskCheckConfig) osutil.RiskResult {
	if r := n.Interpreter.CheckRisk(cfg); r.Level == osutil.Untrusted {
		return r
	}
	opts := resolveOpts(cfg, "node")
	if !opts.Enabled {
		return osutil.RiskResult{Level: osutil.Trusted}
	}
	if r := n.checkDangerousEnv("node", nodeDangerousEnvPrefixes, opts.TrustedEnv); r.Level == osutil.Untrusted {
		return r
	}
	if r := n.checkDangerousArgs("node", nodeDangerousArgs, nil); r.Level == osutil.Untrusted {
		logger.Debug("[Node.CheckRisk] FAIL dangerous-args pid=%d reason=%q", n.GetPid(), r.Reason)
		return r
	}

	if r := n.checkScriptTrust("node", n, cfg); r.Level == osutil.Untrusted {
		logger.Debug("[Node.CheckRisk] FAIL script-trust pid=%d reason=%q", n.GetPid(), r.Reason)
		return r
	}

	return osutil.RiskResult{Level: osutil.Trusted}
}
