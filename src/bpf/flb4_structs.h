#ifndef __FPB4_CORE_STRUCTS_H__
#define __FPB4_CORE_STRUCTS_H__

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct addres {
    __u32 addr;
    __u16 port;
};

struct session_description {
    struct addres subnet;
    struct addres real;

    __u8 flags;
};

struct reverse_description {
    struct addres client;
    struct addres vip;
};

enum packet_flow {
    revers = 1,
    straight
};

#endif