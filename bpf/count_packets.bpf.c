#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u64);
} packets SEC(".maps");

SEC("tc")
int count_packets(struct __sk_buff *skb)
{
    __u32 ifindex = skb->ifindex;
    __u64 one = 1;
    __u64 *count;

    count = bpf_map_lookup_elem(&packets, &ifindex);

    if (count) {
        *count += 1;
    } else {
        bpf_map_update_elem(&packets, &ifindex, &one, BPF_NOEXIST);
    }

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";

