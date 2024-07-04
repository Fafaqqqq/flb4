#include "flb4.usr.h"

#include <err.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <linux/bpf.h>
#include <linux/if_link.h>

int main(int argc, char** argv) {
    __u32 flags = 0;

    auto bpf_obj = flb4_core::open_and_load();

    if (!bpf_obj)
        return -1;

    bpf_xdp_attach(2, -1, flags, nullptr);
    bpf_xdp_attach(2, bpf_program__fd(bpf_obj->progs.balancer_main), flags, nullptr);

cleanup:
    flb4_core::destroy(bpf_obj);
}