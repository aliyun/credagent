package osutil

import "sync"

// CmdlineProvider provides tamper-proof command line strings for processes.
// Implementations include eBPF-based capture and /proc fallback.
type CmdlineProvider interface {
	Lookup(pid uint32) (string, bool)
}

var (
	globalCmdlineProvider CmdlineProvider
	cmdlineProviderMu     sync.RWMutex
)

// SetCmdlineProvider sets the global cmdline provider.
// Should be called once at startup after configuration is loaded.
func SetCmdlineProvider(p CmdlineProvider) {
	cmdlineProviderMu.Lock()
	defer cmdlineProviderMu.Unlock()
	globalCmdlineProvider = p
}

// GetCmdlineProvider returns the current global cmdline provider (may be nil).
func GetCmdlineProvider() CmdlineProvider {
	cmdlineProviderMu.RLock()
	defer cmdlineProviderMu.RUnlock()
	return globalCmdlineProvider
}
