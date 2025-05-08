#ifndef PARSER_H
#define PARSER_H

#include "common.h"

// Ethernet header (simplified for clarity)
typedef struct ethernet_header {
    uint8_t  dst_mac[6];
    uint8_t  src_mac[6];
    uint16_t type;
} ethernet_header_t;

// IP packet info structure 
typedef struct {
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint16_t length;
    uint8_t ttl;
    
    // TCP specific fields
    struct {
        uint8_t fin;
        uint8_t syn;
        uint8_t rst;
        uint8_t psh;
        uint8_t ack;
        uint8_t urg;
        uint32_t seq;
        uint32_t ack_seq;
        uint16_t window;
    } tcp_info;
    
    // Timestamp when the packet was captured
    struct timeval timestamp;
    
    // Raw packet data and size
    const u_char *packet_data;
    int packet_size;
} packet_info_t;

// Function declarations
void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet);
packet_info_t* parse_packet(const struct pcap_pkthdr *pkthdr, const u_char *packet, int datalink_type);
void print_packet_info(const packet_info_t *info);
void free_packet_info(packet_info_t *info);

#endif // PARSER_H