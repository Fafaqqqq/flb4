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
#include "flb4_helper.h"

static __u32 rs_index     = 1;
static __u32 subnet_port  = SUBNET_DEFAULT_PORT;

static __always_inline
int pass_packet(struct xdp_md* ctx) {
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

            return bpf_redirect(fib_attrs.ifindex, 0);
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


static __always_inline
int build_packet(struct iphdr* iph, struct tcphdr* tcph, struct session_info* session) {

    iph->saddr = bpf_htonl(session->subnet.addr);
    iph->daddr = bpf_htonl(session->real.addr);

    tcph->source = bpf_htons(session->subnet.port);
    tcph->dest   = bpf_htons(session->real.port);

    iph->check = 0;
    iph->check = ipv4_chksum(0, iph);

    struct chksum_meta old_meta = {
        .saddr = iph->saddr,
        .daddr = iph->daddr,

        .sport = tcph->source,
        .dport = tcph->dest
    };

    struct chksum_meta new_meta = {
        .saddr = session->subnet.addr,
        .daddr = session->real.addr,

        .sport = session->subnet.port,
        .dport = session->real.port
    };

    tcph->check = tcp_csum(tcph->check, &old_meta, &new_meta);

    return 0;
}

static __always_inline
int process_packet(struct xdp_md* ctx, void* data, void* data_end, __u64 offset) {

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

    if (!session) {
        if (tcph->syn && !(tcph->ack)) {
            incr_dst(&rs_index, &subnet_port, &real_servers_map);

            struct session_info new_session = {
                .flags = F_SYN,

                .vip.addr = bpf_ntohl(iph->daddr),
                .vip.port = bpf_ntohs(tcph->dest),

                .real.addr = *(__u32*)bpf_map_lookup_elem(&real_servers_map, &rs_index),
                .real.port = tcph->dest,

                .subnet.addr = 0,
                .subnet.port = subnet_port
            };

            if (0 != bpf_map_update_elem(&session_map, &addr, &new_session, BPF_NOEXIST)) {

            }
        }
    } else {
        if (tcph->ack && !(tcph->syn)) {
            session->flags |= F_ACK;
        }

        if (session->flags & F_CONNECTED) {
            iph->saddr = bpf_htonl(session->subnet.addr);
            iph->daddr = bpf_htonl(session->real.addr);

            tcph->source = bpf_htons(session->subnet.port);
            tcph->dest   = bpf_htons(session->real.port);
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