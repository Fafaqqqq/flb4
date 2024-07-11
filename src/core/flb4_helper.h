#ifndef __FLB4_CORE_HELPER_H__
#define __FLB4_CORE_HELPER_H__

#include <bpf/bpf_helpers.h>

// Заголовки сетевого стека
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <sys/cdefs.h>

#define VALIDATE_HEADER(ptr, end)   \
	if ((void*)(ptr + 1) > end) { \
		return XDP_PASS;            \
	}

#endif