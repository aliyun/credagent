//go:build linux

package cmdline

import (
	"fmt"

	"github.com/alibaba/CredAgent/internal/execsnoop"
)

type ebpfSource struct {
	snoop execsnoop.ExecSnoop
}

func newEbpfSource() (*ebpfSource, error) {
	snoop := execsnoop.New()
	if !snoop.Available() {
		return nil, fmt.Errorf("eBPF tracepoints not firing or not supported")
	}
	return &ebpfSource{snoop: snoop}, nil
}

func (s *ebpfSource) Name() string              { return "ebpf" }
func (s *ebpfSource) Available() bool            { return s.snoop.Available() }
func (s *ebpfSource) Lookup(pid uint32) (string, bool) { return s.snoop.Lookup(pid) }
func (s *ebpfSource) Close()                     { s.snoop.Close() }
