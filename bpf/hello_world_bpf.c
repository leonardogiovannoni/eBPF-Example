#include <uapi/linux/bpf.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#define __attribute_const__ __attribute__((const))
#include <uapi/linux/if_ether.h>
#include <stddef.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ptrace.h>

#define PTR_AT(ctx, offset, type) \
    (((void *)(long)(ctx)->data + (offset) + sizeof(type) <= (void *)(long)(ctx)->data_end) ? \
    (type *)((void *)(long)(ctx)->data + (offset)) : \
    (type *)(NULL))

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 256);
} EVENTS SEC(".maps");

SEC("xdp")
int get_ip_source(struct xdp_md *ctx) {
    struct ethhdr *ethhdr = PTR_AT(ctx, 0, struct ethhdr);

    if (!ethhdr)
        return XDP_ABORTED;

    if (ethhdr->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iphdr = PTR_AT(ctx, sizeof(*ethhdr), struct iphdr);
    if (!iphdr)
        return XDP_ABORTED;

    struct iphdr iph = *iphdr;
    bpf_perf_event_output(ctx, &EVENTS, BPF_F_CURRENT_CPU, &iph, sizeof(iph));
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

