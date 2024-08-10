#ifndef __FLB4_CORE_HELPER_H__
#define __FLB4_CORE_HELPER_H__

#include <linux/types.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "flb4_consts.h"
#include "flb4_defs.h"
#include "flb4_maps.h"

static __u32 real_server_idx = 1;
static __u32 subnet_idx      = 1;
static __u32 subnet_port     = 1025;

static __always_inline
int get_next_subnet(struct node* subnet) {
    if (NULL == subnet)
        return -__LINE__;

    __u32* sub_addr = (__u32*)bpf_map_lookup_elem(&subnet_map_array, &subnet_idx);

    if (NULL == sub_addr)
        return -__LINE__;

    subnet->addr = *sub_addr;            // Network Byte Order
    subnet->port =  bpf_ntohs(subnet_port); // Network Byte Order

    __u32  sub_count_idx = 0;
    __u32* sub_count     = (__u32*)bpf_map_lookup_elem(&subnet_map_array, &sub_count_idx);

    if (NULL == sub_count)
        return -__LINE__;

    subnet_idx++;
    subnet_idx = subnet_idx % (*sub_count + 1);

    if (0 == subnet_idx) {
        subnet_idx = 1;

        subnet_port++;
        subnet_port = subnet_port % 0xFFFF;

        if (subnet_port == 0) {
            subnet_port = SUBNET_DEFAULT_PORT;
        }
    }

    return 0;
}

static __always_inline
int get_next_rs(struct node* rs) {
    if (NULL == rs)
        return -__LINE__;

    TRACE("rs_idx %d", real_server_idx);
    __u32* rs_addr  = (__u32*)bpf_map_lookup_elem(&rs_map_array, &real_server_idx);

    if (NULL == rs_addr)
        return -__LINE__;

    rs->addr = *rs_addr; // Network Byte Order

    __u32  rs_count_idx = 0;
    __u32* rs_count     = (__u32*)bpf_map_lookup_elem(&rs_map_array, &rs_count_idx);

    if (!rs_count)
        return -__LINE__;

    real_server_idx++;
    real_server_idx = real_server_idx % (*rs_count + 1);


    if (0 == real_server_idx) {
        real_server_idx = 1;
    }

    return 0;
}

#endif