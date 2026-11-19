#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("tracepoint/sched/sched_process_exec")
int handle_exec(void *ctx) {
    bpf_printk("BADGER: exec tracepoint intercepted\n");
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
