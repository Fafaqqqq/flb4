#ifndef __FLB4_CORE_MAPS_H__
#define __FLB4_CORE_MAPS_H__

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "flb4_consts.h"
#include "flb4_structs.h"

// map, which contains all the vips for which we are doing load balancing
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u32);
  __type(value, struct vs_info);
  __uint(max_entries, MAX_VS);
  __uint(map_flags, NO_FLAGS);
} vs_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u8);
  __type(value, __u32);
  __uint(max_entries, 1);
  __uint(map_flags, NO_FLAGS);
} real_servers_count SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, 16);
  __uint(map_flags, NO_FLAGS);
} real_servers_map SEC(".maps");

#endif