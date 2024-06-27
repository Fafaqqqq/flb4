#ifndef __FLB4_CORE_MAPS_H__
#define __FLB4_CORE_MAPS_H__

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "flb4_consts.h"

// map, which contains all the vips for which we are doing load balancing
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct vip_definition);
  __type(value, struct vip_meta);
  __uint(max_entries, MAX_VIPS);
  __uint(map_flags, NO_FLAGS);
} vip_map SEC(".maps");

#endif