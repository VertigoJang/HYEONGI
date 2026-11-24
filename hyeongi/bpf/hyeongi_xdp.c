// SPDX-License-Identifier: MIT OR GPL-2.0
/* HYEONGI XDP enforcement program.
 *
 * Drops packets whose source address is in a pinned hash map:
 *   hyeongi_block   IPv4 (key: 4-byte address in network byte order)
 *   hyeongi_block6  IPv6 (key: 16-byte address in network byte order)
 * value: expiry as CLOCK_MONOTONIC nanoseconds; 0 = never expires. Expired
 * entries are removed lazily here, on the next packet from that source.
 *
 * IPv6 entries are exact addresses (/128). A host that rotates addresses
 * inside its /64 is not covered by one entry.
 *
 * Built and loaded by `python3 -m hyeongi.xdp load`; maps are pinned under
 * /sys/fs/bpf/hyeongi so detectors can update them with bpftool.
 * Dual-licensed MIT/GPL: MIT like the rest of HYEONGI, and "Dual MIT/GPL" is
 * on the kernel's list of GPL-compatible BPF program licenses.
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 200000);
	__type(key, __u32);
	__type(value, __u64);
} hyeongi_block SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 200000);
	__type(key, struct in6_addr);
	__type(value, __u64);
} hyeongi_block6 SEC(".maps");

/* [0] packets dropped, [1] expired entries removed */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} hyeongi_stats SEC(".maps");

static __always_inline void count(__u32 idx)
{
	__u64 *c = bpf_map_lookup_elem(&hyeongi_stats, &idx);
	if (c)
		(*c)++;
}

/* XDP_DROP if `key` is blocked and not expired; an expired entry is deleted. */
static __always_inline int verdict(void *map, void *key)
{
	__u64 *expiry = bpf_map_lookup_elem(map, key);

	if (!expiry)
		return XDP_PASS;
	if (*expiry && bpf_ktime_get_ns() > *expiry) {
		bpf_map_delete_elem(map, key);
		count(1);
		return XDP_PASS;
	}
	count(0);
	return XDP_DROP;
}

SEC("xdp")
int hyeongi_xdp(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;

	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *ip = (void *)(eth + 1);
		__u32 src;

		if ((void *)(ip + 1) > data_end)
			return XDP_PASS;
		src = ip->saddr;
		return verdict(&hyeongi_block, &src);
	}

	if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = (void *)(eth + 1);
		struct in6_addr src6;

		if ((void *)(ip6 + 1) > data_end)
			return XDP_PASS;
		__builtin_memcpy(&src6, &ip6->saddr, sizeof(src6));
		return verdict(&hyeongi_block6, &src6);
	}

	return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
