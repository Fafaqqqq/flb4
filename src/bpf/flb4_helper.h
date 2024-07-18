#ifndef __FLB4_CORE_HELPER_H__
#define __FLB4_CORE_HELPER_H__

#include <bpf/bpf_helpers.h>

// Заголовки сетевого стека
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <sys/cdefs.h>

#include "flb4_consts.h"

static __always_inline
void incr_dst(__u32* idx, __u32* port, void* rs_map) {
    __u32 rs_count_idx = 0;
    __u32 rs_count     = *(__u32*)bpf_map_lookup_elem(&rs_map, &idx);

    (*idx)++;
     *idx = *idx % rs_count;

    if (0 == idx) {
        *idx = 1;

        (*port)++;
        *port = *port % 0xFFFF;

        if (*port == 0) {
            *port = SUBNET_DEFAULT_PORT;
        }
    }
}

#endif