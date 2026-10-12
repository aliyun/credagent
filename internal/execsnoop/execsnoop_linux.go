//go:build linux

package execsnoop

import (
	"bytes"
	"fmt"
	"os"
	"unsafe"

	"github.com/aliyun/credagent/pkg/logger"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cc clang execsnoop bpf/execsnoop.c

const maxCmdlineLen = 512

// bpfExecEvent mirrors struct exec_event in the eBPF C program.
type bpfExecEvent struct {
	PID        uint32
	TGID       uint32
	CmdlineLen uint32
	Cmdline    [maxCmdlineLen]byte
}

type linuxExecSnoop struct {
	objs  *execsnoopObjects
	links []link.Link
}

func New() ExecSnoop {
	if err := checkSyscallTracepoints(); err != nil {
		logger.Warn("eBPF execsnoop: syscall tracepoints not available: %v (falling back to /proc cmdline)", err)
		return &noopExecSnoop{}
	}
	snoop, err := newLinuxExecSnoop()
	if err != nil {
		logger.Warn("eBPF execsnoop not available: %v (falling back to /proc cmdline)", err)
		return &noopExecSnoop{}
	}
	logger.Info("eBPF execsnoop loaded successfully — cmdline tamper detection enabled")
	return snoop
}

func newLinuxExecSnoop() (*linuxExecSnoop, error) {
	if err := checkBPFSupport(); err != nil {
		return nil, fmt.Errorf("BPF not supported: %w", err)
	}

	objs := &execsnoopObjects{}
	if err := loadExecsnoopObjects(objs, nil); err != nil {
		return nil, fmt.Errorf("failed to load eBPF objects: %w", err)
	}

	var links []link.Link

	enterLink, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TracepointSysEnterExecve, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("failed to attach sys_enter_execve: %w", err)
	}
	links = append(links, enterLink)

	exitLink, err := link.Tracepoint("syscalls", "sys_exit_execve", objs.TracepointSysExitExecve, nil)
	if err != nil {
		closeLinks(links)
		objs.Close()
		return nil, fmt.Errorf("failed to attach sys_exit_execve: %w", err)
	}
	links = append(links, exitLink)

	processExitLink, err := link.Tracepoint("sched", "sched_process_exit", objs.TracepointSchedProcessExit, nil)
	if err != nil {
		closeLinks(links)
		objs.Close()
		return nil, fmt.Errorf("failed to attach sched_process_exit: %w", err)
	}
	links = append(links, processExitLink)

	return &linuxExecSnoop{objs: objs, links: links}, nil
}

// checkSyscallTracepoints verifies that syscall tracepoints are actually
// registered in the kernel by reading available_events. On WSL2 and similar
// environments, the kernel compiles tracepoint support but never registers
// syscall events at runtime.
func checkSyscallTracepoints() error {
	paths := []string{
		"/sys/kernel/tracing/available_events",
		"/sys/kernel/debug/tracing/available_events",
	}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if bytes.Contains(data, []byte("syscalls:sys_enter_execve")) {
			return nil
		}
		return fmt.Errorf("syscalls:sys_enter_execve not found in %s", p)
	}
	return fmt.Errorf("cannot read available_events (tracing filesystem not accessible)")
}

func (s *linuxExecSnoop) Available() bool { return true }

func (s *linuxExecSnoop) Lookup(pid uint32) (string, bool) {
	var event bpfExecEvent
	if err := s.objs.ExecEvents.Lookup(pid, unsafe.Pointer(&event)); err != nil {
		return "", false
	}

	n := int(event.CmdlineLen)
	if n > maxCmdlineLen {
		n = maxCmdlineLen
	}
	buf := bytes.TrimRight(event.Cmdline[:n], "\x00")
	for i, b := range buf {
		if b == 0 {
			buf[i] = ' '
		}
	}
	return string(buf), true
}

func (s *linuxExecSnoop) Close() {
	closeLinks(s.links)
	if s.objs != nil {
		s.objs.Close()
	}
}

func closeLinks(links []link.Link) {
	for _, l := range links {
		l.Close()
	}
}

func checkBPFSupport() error {
	_, err := os.Stat("/sys/kernel/btf/vmlinux")
	if err != nil {
		return fmt.Errorf("BTF not available (kernel may be too old or CONFIG_DEBUG_INFO_BTF not enabled): %w", err)
	}

	attr := &ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	}
	m, err := ebpf.NewMap(attr)
	if err != nil {
		return fmt.Errorf("cannot create BPF map (missing CAP_BPF?): %w", err)
	}
	m.Close()
	return nil
}
