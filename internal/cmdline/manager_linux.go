//go:build linux

package cmdline

import "github.com/aliyun/credagent/pkg/logger"

// NewManager creates a Manager based on the cmdline_trusted_source config value.
// It tries each configured source in order; sources that fail to initialize are skipped.
func NewManager(sources []string) *Manager {
	m := &Manager{}
	if len(sources) == 0 {
		logger.Info("cmdline_trusted_source not configured — using /proc/<pid>/cmdline only")
		return m
	}

	logger.Info("cmdline_trusted_source: %v", sources)

	for _, name := range sources {
		switch name {
		case "ebpf":
			src, err := newEbpfSource()
			if err != nil {
				logger.Warn("eBPF cmdline source unavailable: %v", err)
				continue
			}
			m.sources = append(m.sources, src)
			logger.Info("Cmdline trusted source active: ebpf")

		case "auditd":
			src, err := newAuditdSource()
			if err != nil {
				logger.Warn("auditd cmdline source unavailable: %v", err)
				continue
			}
			m.sources = append(m.sources, src)
			logger.Info("Cmdline trusted source active: auditd")

		default:
			logger.Warn("Unknown cmdline_trusted_source value: %q — ignored", name)
		}
	}

	if len(m.sources) == 0 {
		logger.Warn("No cmdline trusted source available — using /proc/<pid>/cmdline only (script cmdline tamper detection degraded)")
	}
	return m
}
