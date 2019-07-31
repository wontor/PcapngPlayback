#ifndef PCAPNG_H
#define PCAPNG_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif


#define BLOCK_SECTION_HEADER        0x0A0D0D0A
#define BLOCK_INTERFACE             0x00000001
#define BLOCK_PACKET_OBSOLETE       0x00000002
#define BLOCK_SIMPLE_PACKET         0x00000003
#define BLOCK_RESOLUTION            0x00000004
#define BLOCK_INTERFACE_STATISTICS  0x00000005
#define BLOCK_ENHANCED_PACKET       0x00000006
#define BLOCK_CUSTOM_DATA           0xB16B00B5
#define BLOCK_UNKNOWN_DATA          0xDEADBEEF

typedef signed char        int8_t;
typedef short              int16_t;
typedef int                int32_t;
typedef long long          int64_t;
typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef unsigned long long uint64_t;

unsigned short ntohs (unsigned short x);

typedef struct _udp_info{
    uint8_t src_ip[4];
    uint8_t dest_ip[4];
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t datagram_len;
    uint8_t* datagram;
    uint32_t timestamp_high, timestamp_low;
    struct _udp_info* next_udp;
}UDPInfo;

UDPInfo *init_udp_info();
void del_udp_info(UDPInfo* udpinfo);
UDPInfo* parse_raw_packet(uint8_t* packet_data);

typedef struct _enhanced_packet_block{
    uint32_t interface_id;
	uint32_t timestamp_high, timestamp_low;
	uint32_t capture_packet_length;
	uint32_t original_capture_length;
	uint8_t* packet_data;
    UDPInfo* udp_info;
}EnhancedPacketBlock;

uint32_t parse_mem(UDPInfo **header, const uint8_t *memory, const size_t size);
uint32_t parse_file(const char *file_name, UDPInfo** head);
void free_udps(UDPInfo* header);

#ifdef __cplusplus
}
#endif
#endif // PCAPNG_H
