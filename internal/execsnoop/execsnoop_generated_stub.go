//go:build linux && !386 && !amd64

// Stub for Linux architectures without pre-compiled eBPF bytecode.
// On amd64/386, bpf2go-generated code in execsnoop_x86_bpfel.go is used instead.

package execsnoop

import "github.com/cilium/ebpf"

type execsnoopObjects struct {
	execsnoopPrograms
	execsnoopMaps
	execsnoopVariables
}

func (o *execsnoopObjects) Close() error { return nil }

type execsnoopPrograms struct {
	TracepointSchedProcessExit *ebpf.Program `ebpf:"tracepoint_sched_process_exit"`
	TracepointSysEnterExecve   *ebpf.Program `ebpf:"tracepoint_sys_enter_execve"`
	TracepointSysExitExecve    *ebpf.Program `ebpf:"tracepoint_sys_exit_execve"`
}

func (p *execsnoopPrograms) Close() error { return nil }

type execsnoopMapSpecs struct {
	ExecEvents  *ebpf.MapSpec `ebpf:"exec_events"`
	ExecHeap    *ebpf.MapSpec `ebpf:"exec_heap"`
	ExecStaging *ebpf.MapSpec `ebpf:"exec_staging"`
}

type execsnoopMaps struct {
	ExecEvents  *ebpf.Map `ebpf:"exec_events"`
	ExecHeap    *ebpf.Map `ebpf:"exec_heap"`
	ExecStaging *ebpf.Map `ebpf:"exec_staging"`
}

func (m *execsnoopMaps) Close() error { return nil }

type execsnoopVariables struct{}

func loadExecsnoopObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	return ebpf.ErrNotSupported
}
