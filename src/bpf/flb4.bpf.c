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
#include "flb4_consts.h"
#include "flb4_defs.h"
#include "flb4_chksum.h"
#include "flb4_maps.h"
#include "flb4_helper.h"
#include "flb4_structs.h"

static __always_inline void print_ip(const char* msg, __u32 ip) {
    bpf_printk("%s %d.%d.%d.%d", msg ? msg : "",
                                (ip & 0xFF000000) >> 24,
                                (ip & 0x00FF0000) >> 16,
                                (ip & 0x0000FF00) >> 8,
                                (ip & 0x000000FF));
}


static __always_inline
int pass_packet(struct xdp_md* ctx) {
    if (!ctx)
        return XDP_DROP;

    bpf_printk("passing packet");

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
    fib_attrs.ifindex  = ctx->ingress_ifindex;

    print_ip("fib_attrs.ipv4_src ",bpf_htonl(fib_attrs.ipv4_src));
    print_ip("fib_attrs.ipv4_dst ",bpf_htonl(fib_attrs.ipv4_dst));

    int fib_ret = bpf_fib_lookup(ctx, &fib_attrs, sizeof(fib_attrs), 0);

    bpf_printk("bpf_fib_lookup ret %d", fib_ret);

    switch (fib_ret) {
        case BPF_FIB_LKUP_RET_SUCCESS:         /* lookup successful */
            memcpy(eth->h_dest,   fib_attrs.dmac, ETH_ALEN);
            memcpy(eth->h_source, fib_attrs.smac, ETH_ALEN);

            bpf_printk("redirecing packet to ifindex %d", fib_attrs.ifindex);

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
int build_straight(struct iphdr* iph, struct tcphdr* tcph, struct session_description* session, void* data_end) {

    print_ip("session->subnet.addr", bpf_htonl(session->subnet.addr));

    struct chksum_meta old_meta = {
        .saddr = iph->saddr,
        .daddr = iph->daddr,

        .sport = tcph->source,
        .dport = tcph->dest
    };

    iph->saddr = session->subnet.addr;
    iph->daddr = session->real.addr;

    tcph->source = session->subnet.port;
    tcph->dest   = session->real.port;

    bpf_printk("tcph->source %d ntoh %d", session->subnet.port, bpf_ntohs(session->subnet.port));
    bpf_printk("tcph->dest %d ntoh %d", session->real.port, bpf_ntohs(session->real.port));

    iph->check = 0;
    iph->check = ipv4_chksum(0, iph);

    struct chksum_meta new_meta = {
        .saddr = session->subnet.addr,
        .daddr = session->real.addr,

        .sport = session->subnet.port,
        .dport = session->real.port
    };

    tcph->check = tcp_chksum(tcph->check, &old_meta, &new_meta);

    return XDP_REDIRECT;
}


static __always_inline
int build_revers(struct iphdr* iph, struct tcphdr* tcph, struct reverse_description* session) {
    struct chksum_meta old_meta = {
        .saddr = iph->saddr,
        .daddr = iph->daddr,

        .sport = tcph->source,
        .dport = tcph->dest
    };

    iph->saddr = session->vip.addr;
    iph->daddr = session->client.addr;

    tcph->source = session->vip.port;
    tcph->dest   = session->client.port;

    bpf_printk("tcph->source %d tcph->dest %d", tcph->source, tcph->dest);
    bpf_printk("tcph->source %d tcph->dest %d", bpf_htons(tcph->source), bpf_htons(tcph->dest));

    iph->check = 0;
    iph->check = ipv4_chksum(0, iph);


    struct chksum_meta new_meta = {
        .saddr = session->vip.addr,
        .daddr = session->client.addr,

        .sport = session->vip.port,
        .dport = session->client.port
    };

    tcph->check = tcp_chksum(tcph->check, &old_meta, &new_meta);

    return XDP_REDIRECT;
}

static __always_inline
enum packet_flow detect_flow(struct iphdr* iph) {
    __u32 saddr = iph->saddr;
    __u32* real_addr = bpf_map_lookup_elem(&rs_map, &saddr);

    return NULL == real_addr ? straight : revers;
}

static __always_inline
int process_client_packet(struct iphdr* iph, struct tcphdr* tcph, void* data_end) {
    if (!iph || !tcph)
        return XDP_DROP;
    // bpf_printk("process_client_packet tcph->source %d ntoh %d", tcph->source, bpf_ntohs(tcph->source));
    // bpf_printk("process_client_packet tcph->dest %d ntoh %d", tcph->dest, bpf_htons(tcph->dest));

    struct addres client = {};
    client.addr = iph->saddr;   // Network Byte Order
    client.port = tcph->source; // Network Byte Order

    struct session_description  description = {};
    description.flags       = 0;
    description.real.addr   = 0;
    description.real.port   = 0;
    description.subnet.addr = 0;
    description.subnet.port = 0;

    struct session_description* lookup_result;
    lookup_result = bpf_map_lookup_elem(&session_map, &client);

    if (lookup_result) {
        bpf_printk("found session");
        memcpy(&description, lookup_result, sizeof(description));
    } else {
        bpf_printk("got new session");
    }

    bpf_printk("description.flags & F_CONNECTED = 0x%x", description.flags & F_CONNECTED);
    switch (description.flags & F_CONNECTED) {
        case F_NCONNECTED: {
            // if (!(tcph->syn) && tcph->ack) {
            //     return XDP_DROP;
            // }

            bpf_printk("get tcp.syn");

            struct addres rs = { .port = tcph->dest }; // Network Byte Order

            // Round-robbin select
            if (0 != get_next_rs(&rs)) // Network Byte Order
                return XDP_DROP;
            bpf_printk("got new rs");
            print_ip("rs->addr ", rs.addr);

            // Round-robbin select
            struct addres subnet = {};
            if (0 != get_next_subnet(&subnet)) // Network Byte Order
                return XDP_DROP;

            bpf_printk("got new subnet");
            print_ip("subnet->addr ", subnet.addr);

            description.flags |= F_SYN;
            description.real   = rs;
            description.subnet.addr = subnet.addr;
            description.subnet.port = subnet.port;

            print_ip("process_client_packet subnet.addr", subnet.addr);
            bpf_printk("process_client_packet subnet.port %d", subnet.port);

            struct reverse_description rev = {};
            rev.client.addr   = client.addr;
            rev.client.port   = client.port;
            rev.vip.addr = iph->daddr;
            rev.vip.port = tcph->dest;

            if (0 != bpf_map_update_elem(&revers_map, &subnet, &rev, BPF_NOEXIST)) {
                bpf_printk("session exists");
                return XDP_DROP;
            }
            break;
        }

        case F_SYN | F_SYN_ACK: {
            bpf_printk("case F_SYN | F_SYN_ACK");
            // if (!(tcph->ack))
                // return XDP_DROP;

            if (!(tcph->ack)) {
                bpf_printk("get tcp.ack");
                description.flags |= F_ACK;
            }
            break;
        }
    }

    if (0 != bpf_map_update_elem(&session_map, &client, &description, BPF_ANY)) {
        bpf_printk("cant update session_map");
        return XDP_DROP;
    }

    return build_straight(iph, tcph, &description, data_end);
}


static __always_inline
int process_server_packet(struct iphdr* iph, struct tcphdr* tcph) {
    if (!iph || !tcph)
        return -__LINE__;

    bpf_printk("process_server_packet");

    __u32 addr = iph->daddr;
    __u16 port = tcph->dest;

    struct addres subnet = {};
    subnet.addr = addr;
    subnet.port = port;

    print_ip("process_server_packet subnet.addr", subnet.addr);
    bpf_printk("process_server_packet subnet.port %d", subnet.port);

    struct reverse_description* rev;
    rev = bpf_map_lookup_elem(&revers_map, &subnet);

    if (NULL == rev) {
        bpf_printk("reverse_description not found");
        return XDP_DROP;
    }

    struct addres client = {};
    client.addr = rev->client.addr;
    client.port = rev->client.port;

    struct session_description* session;
    session = bpf_map_lookup_elem(&session_map, &client);

    if (NULL == session) {
        bpf_printk("No session found");
        return XDP_DROP;
    }

    session->flags |= F_SYN_ACK;

    if (0 != bpf_map_update_elem(&session_map, &client, session, BPF_EXIST)) {
        bpf_printk("Can`t update session_map");
        return XDP_DROP;
    }

    return build_revers(iph, tcph, rev);
}

static __always_inline
int process_packet(struct xdp_md* ctx, void* data, void* data_end, __u64 offset) {
    bpf_printk("begin packet proc");

	struct ethhdr* ethh = (struct ethhdr*)data;
	VALIDATE_HEADER(ethh, data_end);

	struct iphdr* iph = data + offset;
	VALIDATE_HEADER(iph, data_end);

    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;


    bpf_printk("packet proto - tcp");

    struct tcphdr* tcph = (struct tcphdr*)(iph + 1);
	VALIDATE_HEADER(tcph, data_end);

    enum packet_flow flow = detect_flow(iph);

    print_ip("recv pack saddr", bpf_htonl(iph->saddr));
    bpf_printk("recv pack port %d", bpf_htonl(tcph->source));
    bpf_printk("recv pack flow %d", (int)flow);

    int action = XDP_DROP;

    if (straight == flow) {
        bpf_printk("packet from client");
        action = process_client_packet(iph, tcph, data_end);
    } else if (revers == flow) {
        bpf_printk("packet from server");
        action = process_server_packet(iph, tcph);
    }

    bpf_printk("process packet ret %d", action);

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

    bpf_printk("recv packet");

	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        return process_packet(ctx, data, data_end, sizeof(struct ethhdr));
	}

	return XDP_PASS;
}

char __license[] SEC("license") = "GPL";