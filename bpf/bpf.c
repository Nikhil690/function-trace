#include <linux/bpf.h>
#include <bpf/bpf_tracing.h>
#include "ctx.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define GO_PARAM1(x) ((x)->ax)
#define GO_PARAM2(x) ((x)->bx)
#define GO_PARAM3(x) ((x)->cx)
#define GO_PARAM4(x) ((x)->di)

struct user_event {
    int user_id;
    char str[15];
    long int timestamp;
};

struct user_return_event {
    char return_value[64];  // String return value (user name)
    long int timestamp;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} greet_params SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} return_params SEC(".maps");

SEC("uprobe/go_test")
int BPF_UPROBE(go_test) {
    struct user_event *e;
    
    /* reserve sample from BPF ringbuf */
    e = bpf_ringbuf_reserve(&greet_params, sizeof(*e), 0);
    if (!e)
        return 0;
    
    /* fill in event data */
    e->user_id = (int)GO_PARAM1(ctx);  // Read integer ID from first parameter
    __builtin_memset(e->str, 0, sizeof(e->str));
    bpf_probe_read_str(&e->str, sizeof(e->str), (void*)GO_PARAM2(ctx));  // Second param (string)
    e->timestamp = bpf_ktime_get_ns();
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uretprobe/go_test_return")
int BPF_URETPROBE(go_test_return) {
    struct user_return_event *e;
    
    /* reserve sample from BPF ringbuf */
    e = bpf_ringbuf_reserve(&return_params, sizeof(*e), 0);
    if (!e)
        return 0;
    
    /* fill in return event data */
    // In Go, string return values are typically returned as a pointer in AX
    // and length in another register, but for simplicity we'll read the pointer
    bpf_probe_read_str(&e->return_value, sizeof(e->return_value), (void*)GO_PARAM1(ctx));
    e->timestamp = bpf_ktime_get_ns();
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}