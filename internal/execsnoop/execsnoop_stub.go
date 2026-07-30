//go:build !linux

package execsnoop

// New returns a noop implementation on non-Linux platforms where eBPF is not available.
func New() ExecSnoop {
	return &noopExecSnoop{}
}
