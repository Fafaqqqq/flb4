#ifndef __FLB4_CORE_HELPER_H__
#define __FLB4_CORE_HELPER_H__

#include <bpf/bpf_helpers.h>

// Заголовки сетевого стека
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <sys/cdefs.h>

#define VALIDATE_HEADER(ptr, end)   \
	if ((void*)(ptr + 1) > end) { \
		return XDP_PASS;            \
	}

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

#endif