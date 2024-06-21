#include <linux/types.h>

#include "flb4_structs.h"

// Заголовки bpf-функций
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <linux/bpf.h>

// Заголовки сетевого стека
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <sys/cdefs.h>

#define CHECK_RANGE(ptr, end)   \
	if ((void*)(ptr + 1) > end) { \
		return XDP_PASS;            \
	}

// Stage 0: Обеспечить подключение с ноутбука к серверу на loopback
SEC("xpd")
int flb4_virt_server(struct xdp_md* ctx) {
	void *begin = (void *)(long)ctx->data;
	void *end   = (void *)(long)ctx->data_end;

	struct ethhdr* eth = (struct ethhdr*)begin;
	CHECK_RANGE(eth, end);

	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		return XDP_PASS;
	}

	struct iphdr* ip = (struct iphdr*)(eth + 1);
	CHECK_RANGE(eth, end);

	if (ip->protocol != IPPROTO_TCP) {
		return XDP_PASS;
	}

	struct tcphdr* tcp = (struct tcphdr*)(ip + 1);
	CHECK_RANGE(tcp, end);

	return XDP_PASS;
}