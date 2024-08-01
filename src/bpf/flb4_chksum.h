#ifndef __FLB4_CHKSUM_H__
#define __FLB4_CHKSUM_H__

#include <linux/types.h>

// Заголовки bpf-функций
#include <bpf/bpf_helpers.h>

// Заголовки сетевого стека
#include <linux/ip.h>
#include <linux/tcp.h>

struct chksum_meta {
    __u32 saddr;
    __u32 daddr;

    __u32 sport;
    __u32 dport;
};

static __always_inline
__u16 csum_fold_helper(__u32 csum) {
    __u32 sum = csum;
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return ~sum;
}

static __always_inline
__u16 ipv4_chksum(__u32 chksum, struct iphdr *iph) {
    chksum = bpf_csum_diff(0, 0, (void*)iph, sizeof(*iph), chksum);
    return csum_fold_helper(chksum);
}

static __always_inline
__u16 tcp_chksum(__u16 seed, struct chksum_meta* old_meta,
                             struct chksum_meta* new_meta) {
    __u32 chksum = seed;

    __u32 old_ports = bpf_htonl((bpf_ntohs(old_meta->dport) << 16) | bpf_ntohs(old_meta->sport));
    __u32 new_ports = bpf_htonl( bpf_ntohs(new_meta->dport) << 16  | bpf_ntohs(new_meta->sport));

    bpf_printk("old_meta: saddr 0x%08x daddr 0x%08x sport %d dport %d", old_meta->saddr,
                                                                        old_meta->daddr,
                                                                        old_meta->sport,
                                                                        old_meta->dport);

    bpf_printk("new_meta: saddr 0x%08x daddr 0x%08x sport %d dport %d", new_meta->saddr,
                                                                        new_meta->daddr,
                                                                        new_meta->sport,
                                                                        new_meta->dport);

    // Вычитаем старые значения псевдозаголовка
    chksum = ~chksum;

    // Добавляем новые значения псевдозаголовка
    chksum = bpf_csum_diff(&old_meta->saddr, 4, &new_meta->saddr, 4, chksum);
    chksum = bpf_csum_diff(&old_meta->daddr, 4, &new_meta->daddr, 4, chksum);
    chksum = bpf_csum_diff(&old_ports, 4, &new_ports, 4, chksum);

    return csum_fold_helper(chksum);
}

#endif