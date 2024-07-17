#ifndef __FPB4_CORE_STRUCTS_H__
#define __FPB4_CORE_STRUCTS_H__

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct vs_info {
    __u8 change_src_ip : 1;
};

struct addres {
    __u32 addr;
    __u16 port;
};

struct session_info {
    struct addres vip;
    struct addres subnet;
    struct addres real;

    __u8 flags;
};


#endif