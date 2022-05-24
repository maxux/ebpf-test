#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#ifndef lock_xadd
#define lock_xadd(ptr, val)	((void) __sync_fetch_and_add(ptr, val))
#endif

struct datarec {
	__u64 rx_packets;
	__u64 rx_bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct datarec));
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(max_entries, 16);

} xdp_stats_map SEC(".maps");

SEC("xdp_test")
int xdp_test_code(struct xdp_md *ctx) {
    struct datarec *rec;
	__u32 key = XDP_PASS;

    rec = bpf_map_lookup_elem(&xdp_stats_map, &key);
    if(!rec)
        return XDP_ABORTED;

    void *data_end = (void *)(long) ctx->data_end;
    void *data = (void *)(long) ctx->data;

    lock_xadd(&rec->rx_packets, 1);

    /*
    const char fmt[] = "pkt now %llu\n";
    bpf_trace_printk(fmt, sizeof(fmt), rec->rx_packets);
    */

    __u64 bytes = data_end - data;
    lock_xadd(&rec->rx_bytes, bytes);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

