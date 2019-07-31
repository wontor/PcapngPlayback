/*
 *  author: wangt@njust.edu.cn
 *  last edited: 2019.07.31
 *
 *  only support UDP now
 */

#include "pcapng.h"

unsigned short ntohs (unsigned short x)
{
    x = (x << 8) | (x >> 8);
    return x;
}

uint32_t PADD32(uint32_t val){
    if (val % 4 == 0){
        return val;
    }else{
        return (val/4+1)*4;
    }
}

UDPInfo *init_udp_info(){
    UDPInfo* udpinfo = (UDPInfo*)malloc(sizeof(UDPInfo));
    udpinfo->datagram = NULL;
    udpinfo->datagram_len = 0;
    udpinfo->next_udp = NULL;
    return udpinfo;
}

void del_udp_info(UDPInfo* udpinfo){
    if (udpinfo == NULL){
        return;
    }

    if (udpinfo->datagram != NULL){
        free(udpinfo->datagram);
        udpinfo->datagram_len = 0;
    }

    free(udpinfo);
    udpinfo = NULL;
}

UDPInfo* parse_ipv4(uint8_t* packet_data, uint32_t header_len){
    if ( packet_data[9] != 17){ //PROTOCOLS = {1: 'ICMP', 2: 'IGMP', 6: 'TCP', 17: 'UDP'}
        return NULL;
    }

    UDPInfo *udp = init_udp_info();
    memcpy(udp->src_ip, packet_data+12,4);
    memcpy(udp->dest_ip, packet_data+16,4);

    packet_data += header_len * 4;
    udp->src_port = ntohs(*((uint16_t*)packet_data));
    udp->dest_port = ntohs(*((uint16_t*)(packet_data+2)));
    udp->datagram_len = ntohs(*((uint16_t*)(packet_data+4)));
    udp->datagram_len -= 8;     //sub header length

    udp->datagram = (uint8_t*)malloc(udp->datagram_len);
    memcpy(udp->datagram, packet_data+8, udp->datagram_len);

    return udp;
}

UDPInfo* parse_raw_packet(uint8_t* packet_data){
    uint16_t ethernet_type = ntohs(*((uint16_t*)(packet_data+12)));

    packet_data += 14;

	switch (ethernet_type) {
	case 0x0800: // Internet Protocol v4
	case 0x86DD: // Internet Protocol v6
		break;
	case 0x8100: // 802.1Q Virtual LAN
		packet_data += 4;
		break;
	case 0x9100: // 802.1Q DoubleTag
		packet_data += 6;
		break;
	default:
        return NULL;
	}

	uint8_t ip_header_length = (*packet_data) & 0b1111;
	uint8_t protocol_version = (*packet_data >> 4) & 0b1111;

	if (protocol_version == 4) {
		return parse_ipv4(packet_data, ip_header_length);
	}
	
    return NULL;
}


// parse memory
uint32_t parse_mem(UDPInfo **header, const uint8_t *memory, const size_t size)
{
    size_t remaining = size;
    uint32_t udp_count = 0;
    *header = NULL;
    UDPInfo* current = NULL;

    while (remaining > 12) {
        const uint32_t *local_data = (const uint32_t *)(memory);
        uint32_t block_type = *local_data++;
        uint32_t block_total_lenght = *local_data++;

        if(block_type == BLOCK_ENHANCED_PACKET){
            EnhancedPacketBlock epb;
            epb.interface_id =  *local_data++;
            epb.timestamp_high = *local_data++;
            epb.timestamp_low = *local_data++;
            epb.capture_packet_length = *local_data++;
            epb.original_capture_length = *local_data++;
            uint32_t actual_len = PADD32(epb.capture_packet_length);

            uint8_t* packet_data = (uint8_t*)malloc(actual_len);
            memcpy(packet_data, local_data, epb.capture_packet_length); // Maybe actual_len?
            UDPInfo* udp = parse_raw_packet(packet_data);
            free(packet_data);

            if(udp != NULL){
                udp->timestamp_high = epb.timestamp_high;
                udp->timestamp_low = epb.timestamp_low;

                if(*header == NULL){
                    current = udp;
                    current->next_udp = NULL;
                    *header = current;
                }else{
                    current->next_udp = udp;
                    current = current->next_udp;
                }

                udp_count++;
            }
        }

        memory += block_total_lenght;
        remaining -= block_total_lenght;
    }

    return udp_count;
}


long file_size(FILE* fd)
{
    long size = 0;
    long current = ftell(fd);

    fseek(fd, 0, SEEK_END);
    size = ftell(fd);
    fseek(fd, current, SEEK_SET);

    return size;
}

uint32_t parse_file(const char *file_name, UDPInfo** head)
{
    FILE * fd;
    if (fopen_s(&fd, file_name, "rb")  != 0){
        printf("error open file");
        return 0;
    }

    long size = file_size(fd);

    uint8_t *memory = (uint8_t*)malloc(size);
    if (memory == NULL) {
        printf("meomory is NULL");
        fclose(fd);
        return 0;
    }

    size_t bytes_read = fread(memory, 1, size, fd);
    *head = NULL;

    uint8_t *buff = memory;
    uint32_t udp_count = parse_mem(head, buff, bytes_read);
    free(memory);

    if (fd)
    {
        fclose(fd);
    }

    return udp_count;
}

void free_udps(UDPInfo* header){
    while(header != NULL){
        UDPInfo* current = header;
        header = header->next_udp;
        del_udp_info(current);
    }
}
