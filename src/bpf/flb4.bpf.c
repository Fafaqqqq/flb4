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
#include <sys/socket.h>
#include <sys/cdefs.h>

// Заголовки ПО
#include "flb4_defs.h"
#include "flb4_chksum.h"
#include "flb4_maps.h"

__attribute__((__always_inline__))
static inline int process_packet(struct xdp_md* ctx, void* data, void* data_end, __u64 offset) {

	struct ethhdr* eth = (struct ethhdr*)data;
	VALIDATE_HEADER(eth, data_end);

	struct iphdr* ip = data + offset;
	VALIDATE_HEADER(ip, data_end);

    bpf_printk("ip->daddr: %d", bpf_ntohl(ip->daddr));

    return XDP_PASS;

    int action  = XDP_PASS;
    int ifindex = 0;

    __u32 old_saddr = ip->saddr;
    __u32 old_daddr = ip->daddr;

    if (ip->daddr == bpf_htonl(VIRTUAL_IP_ETH1) && ip->saddr != bpf_htonl(REAL_IP)) {
		ip->daddr = bpf_htonl(REAL_IP);
		ip->saddr = bpf_htonl(VIRTUAL_IP_ETH2);
        ifindex  = 4;
	}

	if (ip->daddr == bpf_htonl(VIRTUAL_IP_ETH2) && ip->saddr == bpf_htonl(REAL_IP)) {
		ip->saddr = bpf_htonl(VIRTUAL_IP_ETH1);
		ip->daddr = bpf_htonl(SOURCE_IP);
        ifindex = 3;
	}

    if (ifindex > 0) {
        struct bpf_fib_lookup fib_attrs;

        memset(&fib_attrs, 0, sizeof(fib_attrs));

        fib_attrs.family   = AF_INET;
        fib_attrs.ipv4_src = ip->saddr;
        fib_attrs.ipv4_dst = ip->daddr;
        fib_attrs.ifindex  = ifindex;

        int fib_ret = bpf_fib_lookup(ctx, &fib_attrs, sizeof(fib_attrs), 0);

        switch (fib_ret) {
            case BPF_FIB_LKUP_RET_SUCCESS:         /* lookup successful */
                memcpy(eth->h_dest,   fib_attrs.dmac, ETH_ALEN);
                memcpy(eth->h_source, fib_attrs.smac, ETH_ALEN);

                // Пересчитываем контрольную сумму IP-заголовка
                ip->check = 0;
                ip->check = ipv4_chksum(0, ip);

                bpf_printk("protocol: %d", ip->protocol);

                if (ip->protocol == IPPROTO_TCP) {
                    struct tcphdr* tcph = (struct tcphdr* )(ip + 1);
                    VALIDATE_HEADER(tcph, data_end);

                    tcp_chksum(tcph, old_saddr, ip->saddr, old_daddr, ip->daddr);
                }

                action = bpf_redirect(ifindex, 0);
                break;
            case BPF_FIB_LKUP_RET_BLACKHOLE:    /* dest is blackholed; can be dropped */
                action = XDP_DROP;
                break;
            case BPF_FIB_LKUP_RET_NOT_FWDED:    /* packet is not forwarded */
                break;
            default:
                action = XDP_DROP;
        }
    }

	return action;
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