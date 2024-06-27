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


// Константы - вынести в header

#define IP_FRAGMENTED (0x3FFF)

#define SOURCE_IP  (0xC0A800B3)
#define VIRTUAL_IP (0xC0A800C2)
// #define VIRTUAL_IP (0xC0A80079)
#define REAL_IP    (0xC0A80026)

// -----------------------------

static __always_inline void print_ip(const char* msg, __u32 ip) {
    bpf_printk("%s %d.%d.%d.%d", msg ? msg : "",
                                (ip & 0xFF000000) >> 24,
                                (ip & 0x00FF0000) >> 16,
                                (ip & 0x0000FF00) >> 8,
                                (ip & 0x000000FF));
}

static __always_inline __u16 csum_fold_helper(__u32 csum) {
    __u32 sum = csum;
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return ~sum;
}

static __always_inline __u16 ipv4_csum(__u32 csum, struct iphdr *iph) {
    csum = bpf_csum_diff(0, 0, (__be32 *)iph, sizeof(*iph), csum);
    return csum_fold_helper(csum);
}

__attribute__((__always_inline__))
static inline int process_packet(void* data, void* data_end, __u64 offset) {

	struct ethhdr* eth = (struct ethhdr*)data;
	VALIDATE_HEADER(eth, data_end);


	struct iphdr* ip = data + offset;
	VALIDATE_HEADER(ip, data_end);

	// print_ip("ip: ", bpf_ntohl(ip->saddr));

	if (ip->daddr == bpf_htonl(VIRTUAL_IP) && ip->saddr != bpf_htonl(REAL_IP)) {
		ip->daddr = bpf_htonl(REAL_IP);
		ip->saddr = bpf_htonl(VIRTUAL_IP);

		//
		eth->h_dest[0] = 0xd4;
		eth->h_dest[1] = 0xdc;
		eth->h_dest[2] = 0xcd;
		eth->h_dest[3] = 0xf2;
		eth->h_dest[4] = 0xb1;
		eth->h_dest[5] = 0xe8;

		eth->h_source[0] = 0x18;
		eth->h_source[1] = 0xc0;
		eth->h_source[2] = 0x4d;
		eth->h_source[3] = 0x0e;
		eth->h_source[4] = 0xa1;
		eth->h_source[5] = 0x38;
		// Пересчитываем контрольную сумму IP-заголовка
		ip->check = 0;
		ip->check = ipv4_csum(0, ip);

		// return bpf_redirect(2, 0);
		return XDP_TX;
	}

	if (ip->saddr == bpf_htonl(REAL_IP)) {
		ip->saddr = bpf_htonl(VIRTUAL_IP);
		ip->daddr = bpf_htonl(SOURCE_IP);

		eth->h_dest[0] = 0xdc;
		eth->h_dest[1] = 0x21;
		eth->h_dest[2] = 0x5c;
		eth->h_dest[3] = 0x67;
		eth->h_dest[4] = 0x7c;
		eth->h_dest[5] = 0xd5;

		eth->h_source[0] = 0x18;
		eth->h_source[1] = 0xc0;
		eth->h_source[2] = 0x4d;
		eth->h_source[3] = 0x0e;
		eth->h_source[4] = 0xa1;
		eth->h_source[5] = 0x38;

		// Пересчитываем контрольную сумму IP-заголовка
		ip->check = 0;
		ip->check = ipv4_csum(0, ip);

		return XDP_TX;
		// return bpf_redirect(2, 0);
	}



	return XDP_PASS;
}

SEC("xdp/flb4")
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