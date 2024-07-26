#ifndef __FLB4_CORE_CONSTS_H__
#define __FLB4_CORE_CONSTS_H__

#define AF_INET 2

#define MAX_VS 10
#define MAX_RS 4096
#define MAX_SUBNET 512

#define NO_FLAGS 0

#define F_SYN     (1 << 0)
#define F_SYN_ACK (1 << 1)
#define F_ACK     (1 << 2)

#define F_NCONNECTED (0)
#define F_CONNECTED  (F_SYN | F_SYN_ACK | F_ACK)

#define SUBNET_DEFAULT_PORT (1024)

#endif