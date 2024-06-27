#ifndef __FLB4_CORE_HELPER_H__
#define __FLB4_CORE_HELPER_H__

#define VALIDATE_HEADER(ptr, end)   \
	if ((void*)(ptr + 1) > end) { \
		return XDP_PASS;            \
	}

#endif