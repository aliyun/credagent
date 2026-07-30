//go:build !linux

package cmdline

import "github.com/alibaba/CredAgent/pkg/logger"

// NewManager on non-Linux platforms always returns an empty Manager
// since eBPF and auditd are Linux-specific.
func NewManager(sources []string) *Manager {
	if len(sources) > 0 {
		logger.Warn("cmdline_trusted_source is not supported on this platform — ignored")
	}
	return &Manager{}
}
