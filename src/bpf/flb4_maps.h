#ifndef __FLB4_CORE_MAPS_H__
#define __FLB4_CORE_MAPS_H__

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "flb4_consts.h"
#include "flb4_structs.h"

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, MAX_RS);
} rs_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, MAX_RS);
} rs_map_array SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, MAX_RS);
} subnet_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, MAX_RS);
} subnet_map_array SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct addres);
  __type(value, struct reverse_description);
  __uint(max_entries, 10000);
} revers_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_DEVMAP);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, MAX_RS);
} redirect_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct addres);
  __type(value, struct session_description);
  __uint(max_entries, 10000);
} session_map SEC(".maps");



#endif