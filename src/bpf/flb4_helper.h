#ifndef __FLB4_CORE_HELPER_H__
#define __FLB4_CORE_HELPER_H__

#include <bpf/bpf_helpers.h>

// Заголовки сетевого стека
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
// #include <sys/cdefs.h>

#include "flb4_consts.h"
#include "flb4_maps.h"

static __u32 sub_idx  = 1;
static __u32 sub_port = 1025;

static __always_inline
int get_next_subnet(struct addres* subnet) {
    if (NULL == subnet)
        return -__LINE__;

    __u32* sub_addr = (__u32*)bpf_map_lookup_elem(&subnet_map_array, &sub_idx);

    if (NULL == sub_addr)
        return -__LINE__;

    subnet->addr = *sub_addr;            // Network Byte Order
    subnet->port =  bpf_ntohs(sub_port); // Network Byte Order

    __u32  sub_count_idx = 0;
    __u32* sub_count     = (__u32*)bpf_map_lookup_elem(&subnet_map_array, &sub_count_idx);

    if (NULL == sub_count)
        return -__LINE__;

    sub_idx++;
    sub_idx = sub_idx % (*sub_count + 1);

    if (0 == sub_idx) {
        sub_idx = 1;

        sub_port++;
        sub_port = sub_port % 0xFFFF;

        if (sub_port == 0) {
            sub_port = SUBNET_DEFAULT_PORT;
        }
    }

    return 0;
}

static __u32 rs_idx = 1;

static __always_inline
int get_next_rs(struct addres* rs) {
    if (NULL == rs)
        return -__LINE__;

    bpf_printk("rs_idx %d", rs_idx);
    __u32* rs_addr  = (__u32*)bpf_map_lookup_elem(&rs_map_array, &rs_idx);

    if (NULL == rs_addr)
        return -__LINE__;

    rs->addr = *rs_addr; // Network Byte Order

    __u32  rs_count_idx = 0;
    __u32* rs_count     = (__u32*)bpf_map_lookup_elem(&rs_map_array, &rs_count_idx);

    if (!rs_count)
        return -__LINE__;

    rs_idx++;
    rs_idx = rs_idx % (*rs_count + 1);


    if (0 == rs_idx) {
        rs_idx = 1;
    }


    return 0;
}

#endif