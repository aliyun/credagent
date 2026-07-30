package osutil

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"strings"
)

// getExeSHA256 computes the SHA256 hash of an executable file.
func getExeSHA256(exePath string) (string, error) {
	file, err := os.Open(exePath)
	if err != nil {
		return "", fmt.Errorf("failed to open executable %s: %w", exePath, err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("failed to hash %s: %w", exePath, err)
	}

	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

// GetExeSHA256Func is the exported version for use by sub-packages (e.g. interpreter).
var GetExeSHA256Func = getExeSHA256

// isKnownInterpreter checks if the given executable name is a known interpreter.
func isKnownInterpreter(name string) bool {
	knownExact := []string{"java", "nodejs"}
	for _, k := range knownExact {
		if name == k {
			return true
		}
	}

	prefixes := []string{"python", "node", "php", "perl", "ruby"}
	for _, p := range prefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

const briefArgMaxLen = 64

func briefArg(arg string) string {
	if len(arg) <= briefArgMaxLen {
		return arg
	}
	return arg[:10] + "..." + arg[len(arg)-20:]
}

// BriefCmdline compresses a full cmdline string by truncating overly long arguments.
func BriefCmdline(cmdline string) string {
	args := strings.Split(cmdline, " ")
	for i, arg := range args {
		args[i] = briefArg(arg)
	}
	return strings.Join(args, " ")
}
