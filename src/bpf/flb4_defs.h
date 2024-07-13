#ifndef __FLB4_DEFS_H__
#define __FLB4_DEFS_H__

#define VALIDATE_HEADER(ptr, end)  \
	if ((void*)(ptr + 1) > end) {  \
		return XDP_PASS;           \
	}

#ifndef memcpy
    #define memcpy __builtin_memcpy
#endif

#ifndef memset
    #define memset __builtin_memset
#endif

#define SOURCE_IP       (0x0A8CE2F4)
#define VIRTUAL_IP_ETH1 (0x0A8C00C9)
#define VIRTUAL_IP_ETH2 (0x0A9600C8)
#define REAL_IP         (0x0A960064)

#endif