package execsnoop

// ExecSnoop captures original execve cmdline via eBPF before userspace can tamper.
// When eBPF is unavailable, the noop implementation is used and callers
// fall back to /proc/<pid>/cmdline.
type ExecSnoop interface {
	Available() bool
	Lookup(pid uint32) (string, bool)
	Close()
}

// noopExecSnoop is returned when eBPF is not available.
type noopExecSnoop struct{}

func (n *noopExecSnoop) Available() bool               { return false }
func (n *noopExecSnoop) Lookup(pid uint32) (string, bool) { return "", false }
func (n *noopExecSnoop) Close()                        {}
