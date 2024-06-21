#ifndef __FPB4_STRUCTS_H__
#define __FPB4_STRUCTS_H__

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct flow_key {
    __be32 srcaddr;
    __be32 dstaddr;
    __u32  port;
    __u8   proto;
} ;

struct vip_definition {
    __be32 vip;
    __u16  port;
    __u8   proto;
};

struct real_definition {
    __be32 dst;
    __u8 flags;
};

struct session_info {
    __be32 srcaddr;
    __be32 svraddr;
    __u16  srcport;
    __u16  svrport;
};

#endif