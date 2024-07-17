#include <linux/types.h>

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

// Заголовки ПО
#include "flb4_defs.h"
#include "flb4_chksum.h"
#include "flb4_maps.h"

__attribute__((__always_inline__))
static int pass_packet(struct xdp_md* ctx) {
    void* data     = (void *)(long)ctx->data;
    void* data_end = (void *)(long)ctx->data_end;


    struct ethhdr* eth = (struct ethhdr*)data;
	VALIDATE_HEADER(eth, data_end);

	struct iphdr* ip = (struct iphdr*)(eth + 1);
	VALIDATE_HEADER(ip, data_end);

    struct bpf_fib_lookup fib_attrs;
    memset(&fib_attrs, 0, sizeof(fib_attrs));

    fib_attrs.family   = AF_INET;
    fib_attrs.ipv4_src = ip->saddr;
    fib_attrs.ipv4_dst = ip->daddr;
    fib_attrs.ifindex  = *(__u32*)bpf_map_lookup_elem(&redirect_map, &(ctx->ingress_ifindex));

    int fib_ret = bpf_fib_lookup(ctx, &fib_attrs, sizeof(fib_attrs), 0);

    switch (fib_ret) {
        case BPF_FIB_LKUP_RET_SUCCESS:         /* lookup successful */
            memcpy(eth->h_dest,   fib_attrs.dmac, ETH_ALEN);
            memcpy(eth->h_source, fib_attrs.smac, ETH_ALEN);

            return bpf_redirect_map(&redirect_map, ctx->ingress_ifindex, 0);
            break;
        case BPF_FIB_LKUP_RET_BLACKHOLE:    /* dest is blackholed; can be dropped */
            return XDP_DROP;
            break;
        case BPF_FIB_LKUP_RET_NOT_FWDED:    /* packet is not forwarded */
            break;
        default:
            return XDP_DROP;
    }

    return XDP_PASS;
}

/*
1. Принимаем пакет. Запоминаем адрес и порт клиента

*/

static __u32 rs_index     = 1;
static __u32 subnet_port  = 1025;


__attribute__((__always_inline__))
static int process_packet(struct xdp_md* ctx, void* data, void* data_end, __u64 offset) {

	struct ethhdr* ethh = (struct ethhdr*)data;
	VALIDATE_HEADER(ethh, data_end);

	struct iphdr* iph = data + offset;
	VALIDATE_HEADER(iph, data_end);

    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr* tcph = (struct tcphdr*)(iph + 1);
	VALIDATE_HEADER(tcph, data_end);

    struct addres addr = {
        .addr = bpf_ntohl(iph->saddr),
        .port = bpf_ntohs(tcph->source)
    };

    struct session_info* session = (struct session_info*)bpf_map_lookup_elem(&session_map, &addr);

    if (session && session->flags & F_CONNECTED) {
        iph->saddr = session->subnet.addr;
        iph->daddr = session->real.addr;

        tcph->source = session->subnet.port;
        tcph->dest   = session->real.port;
    } else {
        if (tcph->syn && !(tcph->ack)) {
            struct session_info new_session;

            new_session.flags |= F_SYN;

            new_session.vip.addr = bpf_ntohl(iph->daddr);
            new_session.vip.port = bpf_ntohs(tcph->dest);

            new_session.subnet.addr =
        }
    }


	return pass_packet(ctx);
}

SEC("xdp")
int balancer_main(struct xdp_md* ctx) {
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr* eth = (struct ethhdr*)data;
	VALIDATE_HEADER(eth, data_end);

	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        return process_packet(ctx, data, data_end, sizeof(struct ethhdr));
	}

	return XDP_PASS;
}

char __license[] __attribute__((section("license"), used)) = "GPL";