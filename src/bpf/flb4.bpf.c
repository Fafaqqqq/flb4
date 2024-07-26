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

static __always_inline
int pass_packet(struct xdp_md* ctx) {
    if (!ctx)
        return XDP_DROP;

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
int build_straight(struct iphdr* iph, struct tcphdr* tcph, struct session_description* session) {

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

    tcph->check = tcp_chksum(tcph->check, &old_meta, &new_meta);

    return 0;
}

static __always_inline
int build_revers(struct iphdr* iph, struct tcphdr* tcph, struct reverse_description* session) {

    iph->saddr = bpf_htonl(session->vip.addr);
    iph->daddr = bpf_htonl(session->client.addr);

    tcph->source = bpf_htons(session->vip.port);
    tcph->dest   = bpf_htons(session->client.port);

    iph->check = 0;
    iph->check = ipv4_chksum(0, iph);

    struct chksum_meta old_meta = {
        .saddr = iph->saddr,
        .daddr = iph->daddr,

        .sport = tcph->source,
        .dport = tcph->dest
    };

    struct chksum_meta new_meta = {
        .saddr = session->vip.addr,
        .daddr = session->client.addr,

        .sport = session->vip.port,
        .dport = session->client.port
    };

    tcph->check = tcp_chksum(tcph->check, &old_meta, &new_meta);

    return 0;
}

static __always_inline
enum packet_flow detect_flow(struct iphdr* iph) {
    __u32 saddr = bpf_htonl(iph->saddr);

    __u32* real_addr = bpf_map_lookup_elem(&rs_map, &saddr);

    return NULL != real_addr ? straight : revers;
}

static __always_inline
int process_client_packet(struct iphdr* iph, struct tcphdr* tcph) {
    if (!iph || !tcph)
        return XDP_DROP;

    struct addres client = {
        .addr = bpf_ntohl(iph->saddr),
        .port = bpf_ntohs(tcph->source)
    };

    struct session_description  description = {};
    struct session_description* lookup_result = bpf_map_lookup_elem(&session_map, &client);

    if (lookup_result) {
        memcpy(&description, lookup_result, sizeof(description));
    }

    switch (description.flags & F_CONNECTED) {
        case F_NCONNECTED: {
            if (!(tcph->syn) && tcph->ack) {
                return XDP_DROP;
            }

            struct addres rs = { .port = tcph->dest };

            // Round-robbin select
            if (0 != get_next_rs(&rs))
                return XDP_DROP;

            // Round-robbin select
            struct addres subnet;
            if (0 != get_next_subnet(&subnet))
                return XDP_DROP;

            description.flags |= F_SYN;
            description.real   = rs;
            description.subnet = subnet;

            struct reverse_description rev = {
                .client   = client,
                .vip.addr = bpf_htonl(iph->daddr),
                .vip.port = bpf_htons(tcph->dest)
            };

            if (0 != bpf_map_update_elem(&revers_map, &subnet, &rev, BPF_NOEXIST)) {
                return XDP_DROP;
            }

            break;
        }

        case F_SYN | F_SYN_ACK: {
            if (!(tcph->ack))
                return XDP_DROP;

            description.flags |= F_ACK;
        }

        case F_SYN:
        case F_ACK:
        case F_CONNECTED: {
            if (tcph->syn || tcph->ack)
                return XDP_DROP;
        }

        default:
            return XDP_DROP;
    }

    if (0 != bpf_map_update_elem(&session_map, &client, &description, BPF_ANY)) {
        return XDP_DROP;
    }

    return build_straight(iph, tcph, &description);
}

static __always_inline
int process_server_packet(struct iphdr* iph, struct tcphdr* tcph) {
    struct addres subnet = {
        .addr = bpf_ntohl(iph->daddr),
        .port = bpf_ntohs(tcph->dest)
    };

    struct reverse_description* rev = (struct reverse_description*)bpf_map_lookup_elem(&revers_map, &subnet);

    if (NULL == rev)
        return XDP_DROP;

    return build_revers(iph, tcph, rev);
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

    enum packet_flow flow = detect_flow(iph);

    int action = XDP_DROP;

    if (revers == flow) {
        action = process_client_packet(iph, tcph);
    } else if (straight == flow) {
        action = process_server_packet(iph, tcph);
    }

    if (XDP_REDIRECT != action)
        return action;

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

char __license[] SEC("license") = "GPL";