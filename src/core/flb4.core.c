#include <linux/types.h>

// #include "flb4_structs.h"
#include "flb4_helper.h"

// Заголовки bpf-функций
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
// #include <bpf/bpf_tracing.h>
#include <linux/bpf.h>

// Заголовки сетевого стека
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <sys/cdefs.h>

#include "flb4_structs.h"
#include "flb4_maps.h"

static int real_idx = 0;

__attribute__((__always_inline__))
static inline int process_packet(void* data, void* data_end, __u64 offset) {

	struct iphdr* ip = (struct iphdr*)((__u8*)data + offset);
	// struct iphdr* ip = (__u8*)data + offset;
	VALIDATE_HEADER(ip, data_end);

    struct vs_info* info = (struct vs_info*)NULL;

    __u32 vip = bpf_ntohl(ip->daddr);

    info = (struct vs_info*)(bpf_map_lookup_elem(&vs_map, &vip));

    if (!info) {
        return XDP_PASS;
    }

    if (info->change_src_ip) {
        ip->saddr = bpf_htons(vip);
    }

    __u8   real_count_idx = 0;
    __u32* real_count     = (__u32*)(bpf_map_lookup_elem(&real_servers_count, &real_count_idx));

    if (!real_count) {
        return XDP_PASS;
    }

    __u32  real_server_idx = (real_idx++) % *real_count;
    __u32* real_addr = (__u32*)(bpf_map_lookup_elem(&real_servers_map, &real_server_idx));

    ip->daddr = bpf_htonl(*real_addr);

    ip->check = 0;
    ip->check = ipv4_csum(0, ip);

	return XDP_TX;
}

SEC("xdp")
int balancer_main(struct xdp_md* ctx) {
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr* eth = (struct ethhdr*)data;
	VALIDATE_HEADER(eth, data_end);

	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        return process_packet(data, data_end, sizeof(struct ethhdr));
	}

	return XDP_PASS;
}

char __license[] __attribute__((section("license"), used)) = "GPL";