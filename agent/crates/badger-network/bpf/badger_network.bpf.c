#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_RULES 64

#define ACTION_DENY  0
#define ACTION_ALLOW 1

#define PROTO_ANY 0
#define PROTO_TCP 6
#define PROTO_UDP 17

#define AF_INET  2
#define AF_INET6 10

// Cloud metadata IPv4: 169.254.169.254 (0xA9FEA9FE in big endian / network byte order)
#define CLOUD_METADATA_IPV4 0xA9FEA9FE

struct net_rule4_t {
    __u32 ip;       // Network byte order
    __u32 mask;     // Network byte order
    __u16 min_port; // Host byte order
    __u16 max_port; // Host byte order
    __u8  protocol; // 6 = TCP, 17 = UDP, 0 = ANY
    __u8  action;   // 1 = ALLOW, 0 = DENY
    __u8  active;   // 1 = Active, 0 = Inactive
    __u8  pad;
    __u32 priority; // Lower = higher precedence
    __u32 rule_id;
};

struct net_rule6_t {
    __u32 ip[4];    // Network byte order
    __u32 mask[4];  // Network byte order
    __u16 min_port; // Host byte order
    __u16 max_port; // Host byte order
    __u8  protocol; // 6 = TCP, 17 = UDP, 0 = ANY
    __u8  action;   // 1 = ALLOW, 0 = DENY
    __u8  active;   // 1 = Active, 0 = Inactive
    __u8  pad;
    __u32 priority;
    __u32 rule_id;
};

struct net_config_t {
    __u32 default_action;        // 0 = DENY, 1 = ALLOW
    __u32 rule_count4;
    __u32 rule_count6;
    __u32 block_cloud_metadata;  // 1 = enforce automatic metadata blocking
    __u32 log_all_decisions;     // 1 = log all, 0 = log blocked only
    __u32 policy_version;
};

struct net_telemetry_event_t {
    __u64 timestamp_ns;
    __u64 cgroup_id;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u16 family;
    __u16 protocol;
    __u16 dport;
    __u8  action;
    __u8  matched_rule;
    __u32 rule_id;
    __u32 dip4;
    __u32 dip6[4];
    char  comm[16];
    __u32 pad;
};

// Map: Rules for IPv4
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_RULES);
    __type(key, __u32);
    __type(value, struct net_rule4_t);
} rules4_map SEC(".maps");

// Map: Rules for IPv6
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_RULES);
    __type(key, __u32);
    __type(value, struct net_rule6_t);
} rules6_map SEC(".maps");

// Map: Global configuration & policy state
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct net_config_t);
} config_map SEC(".maps");

// Map: Statistics (0: total, 1: allowed, 2: denied)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

// Map: Ring buffer for network connection decisions
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB
} net_events_ringbuf SEC(".maps");

static __always_inline void record_stat(__u32 index) {
    __u64 *val = bpf_map_lookup_elem(&stats_map, &index);
    if (val) {
        __sync_fetch_and_add(val, 1);
    }
}

static __always_inline void emit_telemetry(
    __u16 family,
    __u16 protocol,
    __u16 dport,
    __u8 action,
    __u8 matched_rule,
    __u32 rule_id,
    __u32 dip4,
    const __u32 *dip6
) {
    struct net_telemetry_event_t *e = bpf_ringbuf_reserve(&net_events_ringbuf, sizeof(*e), 0);
    if (!e) return;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();

    e->timestamp_ns = bpf_ktime_get_ns();
    e->cgroup_id = bpf_get_current_cgroup_id();
    e->pid = (__u32)pid_tgid;
    e->tgid = pid_tgid >> 32;
    e->uid = (__u32)uid_gid;
    e->family = family;
    e->protocol = protocol;
    e->dport = dport;
    e->action = action;
    e->matched_rule = matched_rule;
    e->rule_id = rule_id;
    e->dip4 = dip4;

    if (dip6) {
        e->dip6[0] = dip6[0];
        e->dip6[1] = dip6[1];
        e->dip6[2] = dip6[2];
        e->dip6[3] = dip6[3];
    } else {
        e->dip6[0] = 0;
        e->dip6[1] = 0;
        e->dip6[2] = 0;
        e->dip6[3] = 0;
    }

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->pad = 0;
    bpf_ringbuf_submit(e, 0);
}

static __always_inline int evaluate_ipv4(struct bpf_sock_addr *ctx, __u16 protocol) {
    __u32 zero = 0;
    struct net_config_t *cfg = bpf_map_lookup_elem(&config_map, &zero);
    __u32 default_action = ACTION_DENY;
    __u32 block_metadata = 1;
    __u32 rule_count = 0;

    if (cfg) {
        default_action = cfg->default_action;
        block_metadata = cfg->block_cloud_metadata;
        rule_count = cfg->rule_count4;
        if (rule_count > MAX_RULES) rule_count = MAX_RULES;
    }

    __u32 dip = ctx->user_ip4;
    __u16 dport = bpf_ntohl(ctx->user_port) >> 16;
    if (dport == 0) {
        dport = bpf_ntohs((__u16)ctx->user_port);
    }

    record_stat(0); // Total attempts

    // 1. Cloud metadata security invariant
    if (block_metadata && dip == CLOUD_METADATA_IPV4) {
        record_stat(2); // Denied
        emit_telemetry(AF_INET, protocol, dport, ACTION_DENY, 1, 999999, dip, 0);
        return ACTION_DENY;
    }

    // 2. Evaluate rules in priority order
    for (__u32 i = 0; i < MAX_RULES; i++) {
        if (i >= rule_count) break;

        __u32 key = i;
        struct net_rule4_t *r = bpf_map_lookup_elem(&rules4_map, &key);
        if (!r || !r->active) continue;

        // Protocol match
        if (r->protocol != PROTO_ANY && r->protocol != protocol) continue;

        // Port match
        if (dport < r->min_port || dport > r->max_port) continue;

        // Subnet match: (dip & mask) == (rule_ip & mask)
        if ((dip & r->mask) != (r->ip & r->mask)) continue;

        // Rule matched!
        if (r->action == ACTION_ALLOW) {
            record_stat(1); // Allowed
            if (cfg && cfg->log_all_decisions) {
                emit_telemetry(AF_INET, protocol, dport, ACTION_ALLOW, 1, r->rule_id, dip, 0);
            }
            return ACTION_ALLOW;
        } else {
            record_stat(2); // Denied
            emit_telemetry(AF_INET, protocol, dport, ACTION_DENY, 1, r->rule_id, dip, 0);
            return ACTION_DENY;
        }
    }

    // 3. Fallback to default action
    if (default_action == ACTION_ALLOW) {
        record_stat(1);
        if (cfg && cfg->log_all_decisions) {
            emit_telemetry(AF_INET, protocol, dport, ACTION_ALLOW, 0, 0, dip, 0);
        }
        return ACTION_ALLOW;
    } else {
        record_stat(2);
        emit_telemetry(AF_INET, protocol, dport, ACTION_DENY, 0, 0, dip, 0);
        return ACTION_DENY;
    }
}

static __always_inline int evaluate_ipv6(struct bpf_sock_addr *ctx, __u16 protocol) {
    __u32 zero = 0;
    struct net_config_t *cfg = bpf_map_lookup_elem(&config_map, &zero);
    __u32 default_action = ACTION_DENY;
    __u32 block_metadata = 1;
    __u32 rule_count = 0;

    if (cfg) {
        default_action = cfg->default_action;
        block_metadata = cfg->block_cloud_metadata;
        rule_count = cfg->rule_count6;
        if (rule_count > MAX_RULES) rule_count = MAX_RULES;
    }

    __u32 dip[4];
    dip[0] = ctx->user_ip6[0];
    dip[1] = ctx->user_ip6[1];
    dip[2] = ctx->user_ip6[2];
    dip[3] = ctx->user_ip6[3];

    __u16 dport = bpf_ntohl(ctx->user_port) >> 16;
    if (dport == 0) {
        dport = bpf_ntohs((__u16)ctx->user_port);
    }

    record_stat(0); // Total attempts

    // Check cloud metadata IPv6 (fd00:ec2::254 -> 0xfd000ec2, 0, 0, 0x00000254)
    if (block_metadata && dip[0] == 0xfd000ec2 && dip[1] == 0 && dip[2] == 0 && dip[3] == 0x00000254) {
        record_stat(2);
        emit_telemetry(AF_INET6, protocol, dport, ACTION_DENY, 1, 999998, 0, dip);
        return ACTION_DENY;
    }

    // Evaluate rules
    for (__u32 i = 0; i < MAX_RULES; i++) {
        if (i >= rule_count) break;

        __u32 key = i;
        struct net_rule6_t *r = bpf_map_lookup_elem(&rules6_map, &key);
        if (!r || !r->active) continue;

        if (r->protocol != PROTO_ANY && r->protocol != protocol) continue;
        if (dport < r->min_port || dport > r->max_port) continue;

        if (((dip[0] & r->mask[0]) != (r->ip[0] & r->mask[0])) ||
            ((dip[1] & r->mask[1]) != (r->ip[1] & r->mask[1])) ||
            ((dip[2] & r->mask[2]) != (r->ip[2] & r->mask[2])) ||
            ((dip[3] & r->mask[3]) != (r->ip[3] & r->mask[3]))) {
            continue;
        }

        if (r->action == ACTION_ALLOW) {
            record_stat(1);
            if (cfg && cfg->log_all_decisions) {
                emit_telemetry(AF_INET6, protocol, dport, ACTION_ALLOW, 1, r->rule_id, 0, dip);
            }
            return ACTION_ALLOW;
        } else {
            record_stat(2);
            emit_telemetry(AF_INET6, protocol, dport, ACTION_DENY, 1, r->rule_id, 0, dip);
            return ACTION_DENY;
        }
    }

    if (default_action == ACTION_ALLOW) {
        record_stat(1);
        if (cfg && cfg->log_all_decisions) {
            emit_telemetry(AF_INET6, protocol, dport, ACTION_ALLOW, 0, 0, 0, dip);
        }
        return ACTION_ALLOW;
    } else {
        record_stat(2);
        emit_telemetry(AF_INET6, protocol, dport, ACTION_DENY, 0, 0, 0, dip);
        return ACTION_DENY;
    }
}

// -----------------------------------------------------------------------------
// cgroup Socket Address Hooks
// -----------------------------------------------------------------------------

SEC("cgroup/connect4")
int badger_cgroup_connect4(struct bpf_sock_addr *ctx) {
    __u16 proto = (__u16)ctx->protocol;
    if (proto == 0) proto = PROTO_TCP;
    return evaluate_ipv4(ctx, proto);
}

SEC("cgroup/connect6")
int badger_cgroup_connect6(struct bpf_sock_addr *ctx) {
    __u16 proto = (__u16)ctx->protocol;
    if (proto == 0) proto = PROTO_TCP;
    return evaluate_ipv6(ctx, proto);
}

SEC("cgroup/sendmsg4")
int badger_cgroup_sendmsg4(struct bpf_sock_addr *ctx) {
    return evaluate_ipv4(ctx, PROTO_UDP);
}

SEC("cgroup/sendmsg6")
int badger_cgroup_sendmsg6(struct bpf_sock_addr *ctx) {
    return evaluate_ipv6(ctx, PROTO_UDP);
}

char _license[] SEC("license") = "Dual MIT/GPL";
