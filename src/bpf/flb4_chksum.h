#ifndef __FLB4_CHKSUM_H__
#define __FLB4_CHKSUM_H__

#include <linux/types.h>

// Заголовки bpf-функций
#include <bpf/bpf_helpers.h>

// Заголовки сетевого стека
#include <linux/ip.h>
#include <linux/tcp.h>

static __always_inline
__u16 csum_fold_helper(__u32 csum) {
    __u32 sum = csum;
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return ~sum;
}

static __always_inline
__u16 ipv4_chksum(__u32 csum, struct iphdr *iph) {
    csum = bpf_csum_diff(0, 0, (void*)iph, sizeof(*iph), csum);
    return csum_fold_helper(csum);
}

static __always_inline
void tcp_chksum(struct tcphdr *tcph, __u32 old_saddr, __u32 new_saddr,
                                     __u32 old_daddr, __u32 new_daddr) {
    __u32 check = tcph->check;

    // Вычитаем старые значения псевдозаголовка
    check = ~check;

    // Добавляем новые значения псевдозаголовка
    check = bpf_csum_diff(&old_saddr, 4, &new_saddr, 4, check);
    check = bpf_csum_diff(&old_daddr, 4, &new_daddr, 4, check);

    tcph->check = csum_fold_helper(check);
}

#endif