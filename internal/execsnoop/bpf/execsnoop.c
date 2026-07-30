// SPDX-License-Identifier: GPL-2.0
// eBPF program for capturing original execve cmdline before userspace can tamper.
//
// Verifier-friendly pattern (modeled after BCC libbpf-tools/execsnoop.bpf.c):
// - Use a struct field (`cmdline_len`) as the offset, not a local register.
//   Each access re-loads from map memory — the verifier sees a fresh scalar
//   that the bounds check can pin precisely, avoiding state widening across
//   unrolled loop iterations.
// - Read full chunks of size ARG_READ_SIZE; advance offset by `+= ret`,
//   keeping the trailing NUL of each arg as a separator.
//   Userspace converts NULs to spaces.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define MAX_CMDLINE_LEN 512
#define ARG_READ_SIZE   128
#define MAX_ARGS        16
// LAST_ARG is the highest offset at which we can still safely read ARG_READ_SIZE bytes.
#define LAST_ARG        (MAX_CMDLINE_LEN - ARG_READ_SIZE)

struct exec_event {
	u32 pid;
	u32 tgid;
	u32 cmdline_len; // also used as the in-loop write offset
	char cmdline[MAX_CMDLINE_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, struct exec_event);
} exec_staging SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, struct exec_event);
} exec_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct exec_event);
} exec_heap SEC(".maps");

struct sys_enter_execve_args {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	int __syscall_nr;
	const char *filename;
	const char *const *argv;
	const char *const *envp;
};

struct sys_exit_execve_args {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	int __syscall_nr;
	long ret;
};

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint_sys_enter_execve(struct sys_enter_execve_args *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tid = (u32)pid_tgid;
	u32 tgid = pid_tgid >> 32;

	u32 zero = 0;
	struct exec_event *event = bpf_map_lookup_elem(&exec_heap, &zero);
	if (!event)
		return 0;

	event->pid = tid;
	event->tgid = tgid;
	event->cmdline_len = 0;

	const char *const *argv = ctx->argv;
	const char *argp;
	int ret;

	#pragma unroll
	for (int i = 0; i < MAX_ARGS; i++) {
		ret = bpf_probe_read_user(&argp, sizeof(argp), &argv[i]);
		if (ret < 0 || !argp)
			break;

		// Re-load offset from map memory — verifier treats each load as a
		// fresh scalar, so the bound check pins it precisely.
		if (event->cmdline_len > LAST_ARG)
			break;

		ret = bpf_probe_read_user_str(&event->cmdline[event->cmdline_len],
		                              ARG_READ_SIZE, argp);
		if (ret <= 0)
			break;

		// `+= ret` keeps the trailing NUL as a delimiter; userspace converts
		// it to a space. ret is bounded by ARG_READ_SIZE per helper contract.
		event->cmdline_len += ret;
	}

	bpf_map_update_elem(&exec_staging, &tid, event, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int tracepoint_sys_exit_execve(struct sys_exit_execve_args *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tid = (u32)pid_tgid;
	u32 tgid = pid_tgid >> 32;

	struct exec_event *staged = bpf_map_lookup_elem(&exec_staging, &tid);
	if (!staged)
		return 0;

	if (ctx->ret == 0) {
		staged->tgid = tgid;
		bpf_map_update_elem(&exec_events, &tgid, staged, BPF_ANY);
	}

	bpf_map_delete_elem(&exec_staging, &tid);
	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int tracepoint_sched_process_exit(void *ctx)
{
	// sched_process_exit fires for *every* thread exit, not just the
	// process leader. If we delete unconditionally, an internal worker
	// thread of a multi-threaded process (e.g. Python's GIL-related
	// helpers) exiting will wipe out the entry while the main process
	// is still alive, causing later lookups by user-space PID to miss.
	//
	// Filter: only delete when tid == tgid (leader thread exit), which
	// in practice means the process group is finishing.
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tid = (u32)pid_tgid;
	u32 tgid = pid_tgid >> 32;
	if (tid == tgid)
		bpf_map_delete_elem(&exec_events, &tgid);
	return 0;
}

char _license[] SEC("license") = "GPL";
