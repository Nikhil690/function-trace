#include <linux/bpf.h>
#include <bpf/bpf_tracing.h>
#include "ctx.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define GO_PARAM1(x) ((x)->ax)
#define GO_PARAM2(x) ((x)->bx)
#define GO_PARAM3(x) ((x)->cx)
#define GO_PARAM4(x) ((x)->di)
#define GO_PARAM5(x) ((x)->dx)
#define GO_PARAM6(x) ((x)->ip)
#define GO_PARAM7(x) ((x)->sp)

#define MAX_COPY 400
#define MAX_STR_LEN 128

struct go_string {
    const char *ptr;
    unsigned long len;
};


struct user_event {
    __u64 timestamp;
    int Qlen;
    char str[128];
};

struct user_return_event {
    char return_value[64];
    long int timestamp;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 67108864);
} greet_params SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 67108864);
} return_params SEC(".maps");

#define MAX_STR_LEN 128

SEC("uprobe/go_test")
int BPF_UPROBE(go_test) {
    struct user_event *e;
    __s64 raw_len;
    __u32 str_len;

    // Reserve space in ringbuf
    e = bpf_ringbuf_reserve(&greet_params, sizeof(*e), 0);
    if (!e)
        return 0;

    // Read GO_PARAM3 (string length) safely
    raw_len = GO_PARAM3(ctx);
    if (raw_len <= 0 || raw_len >= MAX_STR_LEN) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    e->timestamp = bpf_ktime_get_ns();
    str_len = (__u32)raw_len;
    e->Qlen = str_len;

    // Zero out buffer and read string with bounded length
    __builtin_memset(e->str, 0, sizeof(e->str));
    bpf_probe_read_user(e->str, str_len, (void *)GO_PARAM2(ctx));

    e->str[str_len & (MAX_STR_LEN - 1)] = '\0';


    bpf_printk("user_id = %d, timestamp = %ld", e->Qlen, e->timestamp);

    bpf_ringbuf_submit(e, 0);
    return 0;
}


SEC("uretprobe/go_test_return")
int BPF_URETPROBE(go_test_return) {
    // struct user_return_event *e;
    // e = bpf_ringbuf_reserve(&return_params, sizeof(*e), 0);
    // if (!e)
    //     return 0;

    // // bpf_probe_read_str(&e->return_value, sizeof(e->return_value), (void*)GO_PARAM1(ctx));
    // e->timestamp = bpf_ktime_get_ns();

    // bpf_ringbuf_submit(e, 0);
    // return 0;
    bpf_printk("uretprobe is triggered !\n");
    return 0;
}
