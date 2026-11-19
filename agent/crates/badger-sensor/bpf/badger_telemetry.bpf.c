#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define EVENT_TYPE_EXEC        1
#define EVENT_TYPE_EXIT        2
#define EVENT_TYPE_FORK        3
#define EVENT_TYPE_CONNECT     4
#define EVENT_TYPE_SETUID      5
#define EVENT_TYPE_OPENAT      6
#define EVENT_TYPE_UNLINKAT    7

#define RESOURCE_MAX_LEN       128
#define COMM_MAX_LEN           16

struct badger_bpf_event {
    __u64 timestamp_ns;          // Kernel monotonic timestamp from bpf_ktime_get_ns()
    __u64 cgroup_id;             // Kernel cgroup v2 ID for workload attribution
    __u32 host_pid;              // TGID (Thread Group ID / process ID)
    __u32 host_tid;              // Thread ID
    __u32 parent_pid;            // Parent Process ID
    __u32 uid;                   // User ID
    __u32 gid;                   // Group ID
    __u32 cpu_id;                // CPU Processor Core ID
    __u32 event_type;            // Numeric event category (1..7)
    char  comm[COMM_MAX_LEN];    // Process command name
    char  resource[RESOURCE_MAX_LEN]; // Path, destination IP, or event context
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB bounded kernel ring buffer
} events_ringbuf SEC(".maps");

static __always_inline void init_common_event(struct badger_bpf_event *e, __u32 type) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();

    e->timestamp_ns = bpf_ktime_get_ns();
    e->cgroup_id = bpf_get_current_cgroup_id();
    e->host_pid = pid_tgid >> 32;
    e->host_tid = (__u32)pid_tgid;
    e->parent_pid = 0;
    e->uid = (__u32)uid_gid;
    e->gid = uid_gid >> 32;
    e->cpu_id = bpf_get_smp_processor_id();
    e->event_type = type;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

// Tracepoint: sched/sched_process_exec
struct trace_event_raw_sched_process_exec {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __s32 common_pid;
    __u32 filename_loc;
    __s32 pid;
    __s32 old_pid;
};

SEC("tracepoint/sched/sched_process_exec")
int handle_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
    struct badger_bpf_event *e = bpf_ringbuf_reserve(&events_ringbuf, sizeof(*e), 0);
    if (!e) return 0;

    init_common_event(e, EVENT_TYPE_EXEC);
    e->parent_pid = ctx->old_pid;

    __u16 offset = ctx->filename_loc & 0xFFFF;
    const char *fname = (const char *)ctx + offset;
    bpf_probe_read_str(&e->resource, sizeof(e->resource), fname);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Tracepoint: sched/sched_process_exit
struct trace_event_raw_sched_process_exit {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __s32 common_pid;
    char comm[16];
    __s32 pid;
    __s32 prio;
};

SEC("tracepoint/sched/sched_process_exit")
int handle_process_exit(struct trace_event_raw_sched_process_exit *ctx) {
    struct badger_bpf_event *e = bpf_ringbuf_reserve(&events_ringbuf, sizeof(*e), 0);
    if (!e) return 0;

    init_common_event(e, EVENT_TYPE_EXIT);
    e->resource[0] = '\0';

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Tracepoint: sched/sched_process_fork
struct trace_event_raw_sched_process_fork {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __s32 common_pid;
    char parent_comm[16];
    __s32 parent_pid;
    char child_comm[16];
    __s32 child_pid;
};

SEC("tracepoint/sched/sched_process_fork")
int handle_process_fork(struct trace_event_raw_sched_process_fork *ctx) {
    struct badger_bpf_event *e = bpf_ringbuf_reserve(&events_ringbuf, sizeof(*e), 0);
    if (!e) return 0;

    init_common_event(e, EVENT_TYPE_FORK);
    e->parent_pid = ctx->parent_pid;
    e->host_pid = ctx->child_pid;
    bpf_probe_read_str(&e->resource, sizeof(e->resource), ctx->child_comm);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Tracepoint: syscalls/sys_enter_connect
struct trace_event_raw_sys_enter_connect {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __s32 common_pid;
    __s32 __syscall_nr;
    __u64 fd;
    __u64 uservaddr;
    __u64 addrlen;
};

SEC("tracepoint/syscalls/sys_enter_connect")
int handle_sys_connect(struct trace_event_raw_sys_enter_connect *ctx) {
    struct badger_bpf_event *e = bpf_ringbuf_reserve(&events_ringbuf, sizeof(*e), 0);
    if (!e) return 0;

    init_common_event(e, EVENT_TYPE_CONNECT);

    if (ctx->uservaddr) {
        __u16 family = 0;
        bpf_probe_read(&family, sizeof(family), (void *)ctx->uservaddr);
        if (family == 2) { // AF_INET
            __u16 port = 0;
            __u32 ip = 0;
            bpf_probe_read(&port, sizeof(port), (void *)(ctx->uservaddr + 2));
            bpf_probe_read(&ip, sizeof(ip), (void *)(ctx->uservaddr + 4));

            e->resource[0] = 'a';
            e->resource[1] = 'f';
            e->resource[2] = '_';
            e->resource[3] = 'i';
            e->resource[4] = 'n';
            e->resource[5] = 'e';
            e->resource[6] = 't';
            e->resource[7] = '\0';
        } else {
            e->resource[0] = 'a';
            e->resource[1] = 'f';
            e->resource[2] = '_';
            e->resource[3] = 'o';
            e->resource[4] = 't';
            e->resource[5] = 'h';
            e->resource[6] = 'e';
            e->resource[7] = 'r';
            e->resource[8] = '\0';
        }
    } else {
        e->resource[0] = '\0';
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Tracepoint: syscalls/sys_enter_openat
struct trace_event_raw_sys_enter_openat {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __s32 common_pid;
    __s32 __syscall_nr;
    __u64 dfd;
    __u64 filename;
    __u64 flags;
    __u64 mode;
};

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_sys_openat(struct trace_event_raw_sys_enter_openat *ctx) {
    struct badger_bpf_event *e = bpf_ringbuf_reserve(&events_ringbuf, sizeof(*e), 0);
    if (!e) return 0;

    init_common_event(e, EVENT_TYPE_OPENAT);

    if (ctx->filename) {
        bpf_probe_read_str(&e->resource, sizeof(e->resource), (const char *)ctx->filename);
    } else {
        e->resource[0] = '\0';
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Tracepoint: syscalls/sys_enter_setuid
struct trace_event_raw_sys_enter_setuid {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __s32 common_pid;
    __s32 __syscall_nr;
    __u64 uid;
};

SEC("tracepoint/syscalls/sys_enter_setuid")
int handle_sys_setuid(struct trace_event_raw_sys_enter_setuid *ctx) {
    struct badger_bpf_event *e = bpf_ringbuf_reserve(&events_ringbuf, sizeof(*e), 0);
    if (!e) return 0;

    init_common_event(e, EVENT_TYPE_SETUID);
    e->resource[0] = 'u';
    e->resource[1] = 'i';
    e->resource[2] = 'd';
    e->resource[3] = '_';
    e->resource[4] = 's';
    e->resource[5] = 'e';
    e->resource[6] = 't';
    e->resource[7] = '\0';

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
