#ifndef __FPB4_CORE_STRUCTS_H__
#define __FPB4_CORE_STRUCTS_H__

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct vs_info {
    __u8 change_src_ip : 1;
};


#endif