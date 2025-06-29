#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "ctx.h"

// Define missing types if needed
typedef unsigned int u32;
typedef unsigned long long u64;

#define GO_PARAM1(x) ((x)->ax)
#define GO_PARAM2(x) ((x)->bx)
#define GO_PARAM3(x) ((x)->cx)
#define GO_PARAM4(x) ((x)->di)

struct span_start {
    u32 tid;
    u64 ts;
};

struct func_event {
    u32 tid;
    u64 start_ts;
    u64 end_ts;
    char func[64];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u64);
} func_starts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, u32);
    __type(value, char[256]);
} http_map SEC(".maps");

static __always_inline u32 get_tid()
{
    return bpf_get_current_pid_tgid() & 0xFFFFFFFF;
}

SEC("uprobe")
int generic_func_entry(struct pt_regs *ctx)
{
    u32 tid = get_tid();
    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&func_starts, &tid, &ts, BPF_ANY);
    return 0;
}

SEC("uretprobe")
int generic_func_exit(struct pt_regs *ctx)
{
    u32 tid = get_tid();
    u64 *start_ts = bpf_map_lookup_elem(&func_starts, &tid);
    if (!start_ts) return 0;

    struct func_event fe = {
        .tid = tid,
        .start_ts = *start_ts,
        .end_ts = bpf_ktime_get_ns(),
    };
    
    // Get function name (simplified - in practice you'd need symbol resolution)
    bpf_probe_read_kernel_str(fe.func, sizeof(fe.func), (void *)GO_PARAM1(ctx));
    
    bpf_ringbuf_output(&events, &fe, sizeof(fe), 0);
    bpf_map_delete_elem(&func_starts, &tid);
    return 0;
}

SEC("uprobe/http_handler")
int http_entry(struct pt_regs *ctx)
{
    u32 tid = get_tid();
    struct span_start se = {
        .tid = tid,
        .ts = bpf_ktime_get_ns()
    };
    bpf_ringbuf_output(&events, &se, sizeof(se), 0);
    return 0;
}

char _license[] SEC("license") = "Dual BSD/GPL";