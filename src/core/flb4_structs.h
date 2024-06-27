#ifndef __FPB4_CORE_STRUCTS_H__
#define __FPB4_CORE_STRUCTS_H__

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
    __be32 addr;
    __u16  port;
    __u8   proto;
};

struct vip_meta {
  __u32 flags;
  __u32 vip_num;
};


struct real_definition {
    __be32 addr;
    __u8 flags;
};

struct session_info {
    __be32 srcaddr;
    __be32 svraddr;
    __u16  srcport;
    __u16  svrport;

};

struct client_info {
    __be32 addr;
    __be32 port;
};



#endif