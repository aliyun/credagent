package cmdline

import "github.com/aliyun/credagent/internal/osutil"

// TrustedSource provides pid → original cmdline lookup captured at execve time.
type TrustedSource interface {
	Name() string
	Available() bool
	Lookup(pid uint32) (string, bool)
	Close()
}

// Manager manages multiple TrustedSources and queries them in priority order.
type Manager struct {
	sources []TrustedSource
}

// Lookup tries each source in order and returns the first hit.
func (m *Manager) Lookup(pid uint32) (string, bool) {
	for _, s := range m.sources {
		if cl, ok := s.Lookup(pid); ok {
			return cl, true
		}
	}
	return "", false
}

// LookupFunc returns a CmdlineLookupFunc for use by osutil.ExtractProcContext.
// Returns nil if no sources are available (caller falls back to /proc).
func (m *Manager) LookupFunc() osutil.CmdlineLookupFunc {
	if len(m.sources) == 0 {
		return nil
	}
	return m.Lookup
}

// Close shuts down all sources and releases resources.
func (m *Manager) Close() {
	for _, s := range m.sources {
		s.Close()
	}
	m.sources = nil
}
