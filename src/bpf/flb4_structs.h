#ifndef __FPB4_CORE_STRUCTS_H__
#define __FPB4_CORE_STRUCTS_H__

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

enum packet_direction {
    client_server,
    server_client
};

enum tcp_state {
    tcp_ncon = 0,
    tcp_con,
    tcp_opening,
    tcp_closing,
};

struct node {
    __be32 addr;
    __be16 port;
};

struct reverse_description {
    struct node client;
    struct node vip;
};

struct session_description {

    struct node subnet;
    struct node real;

    enum tcp_state state;
    __u8 flags;
};






#endif