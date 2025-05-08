#include "../include/parser.h"
#include "../include/logger.h"
#include "../include/anomaly.h"

void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // Cast user data to capture session
    int datalink_type = *((int *)user);
    
    // Parse the packet into our structure
    packet_info_t *packet_info = parse_packet(pkthdr, packet, datalink_type);
    
    if (packet_info) {
        // Print packet info to stdout if in debug mode
        #ifdef DEBUG
        print_packet_info(packet_info);
        #endif
        
        // Log the packet
        log_packet(packet_info);
        
        // Check for anomalies
        anomaly_info_t *anomaly = detect_anomalies(packet_info);
        if (anomaly) {
            log_anomaly(anomaly);
            free_anomaly_info(anomaly);
        }
        
        // Free the packet info
        free_packet_info(packet_info);
    }
}

packet_info_t* parse_packet(const struct pcap_pkthdr *pkthdr, const u_char *packet, int datalink_type) {
    packet_info_t *info = (packet_info_t *)malloc(sizeof(packet_info_t));
    if (!info) {
        log_message(LOG_LEVEL_ERROR, "Failed to allocate memory for packet info");
        return NULL;
    }
    
    // Initialize the structure
    memset(info, 0, sizeof(packet_info_t));
    
    // Store the timestamp
    info->timestamp = pkthdr->ts;
    info->packet_data = packet;
    info->packet_size = pkthdr->len;
    
    // Get the Ethernet header based on datalink type
    const struct ether_header *eth_header = NULL;
    const struct ip *ip_header = NULL;
    int ethernet_header_size = 0;
    
    switch (datalink_type) {
        case DLT_EN10MB:
            eth_header = (struct ether_header *)packet;
            ethernet_header_size = sizeof(struct ether_header);
            
            // Check if it's an IP packet
            if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
                // Not an IP packet
                return info;
            }
            
            // Get IP header
            ip_header = (struct ip *)(packet + ethernet_header_size);
            break;
            
        case DLT_LINUX_SLL:  // Linux cooked capture
            ethernet_header_size = 16;  // SLL header size
            ip_header = (struct ip *)(packet + ethernet_header_size);
            break;
            
        case DLT_NULL:  // BSD loopback
            ethernet_header_size = 4;
            ip_header = (struct ip *)(packet + ethernet_header_size);
            break;
            
        default:
            log_message(LOG_LEVEL_ERROR, "Unsupported datalink type: %d", datalink_type);
            free(info);
            return NULL;
    }
    
    // Store IP addresses
    inet_ntop(AF_INET, &(ip_header->ip_src), info->src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), info->dst_ip, INET_ADDRSTRLEN);
    
    // Store general IP info
    info->protocol = ip_header->ip_p;
    info->ttl = ip_header->ip_ttl;
    info->length = ntohs(ip_header->ip_len);
    
    // Get protocol-specific information
    int ip_header_size = ip_header->ip_hl * 4;  // IP header length in bytes
    
    switch (info->protocol) {
        case IPPROTO_TCP: {
            const struct tcphdr *tcp_header = (struct tcphdr *)((u_char *)ip_header + ip_header_size);
            info->src_port = ntohs(tcp_header->th_sport);
            info->dst_port = ntohs(tcp_header->th_dport);
            
            // TCP flags
            info->tcp_info.fin = (tcp_header->th_flags & TH_FIN) != 0;
            info->tcp_info.syn = (tcp_header->th_flags & TH_SYN) != 0;
            info->tcp_info.rst = (tcp_header->th_flags & TH_RST) != 0;
            info->tcp_info.psh = (tcp_header->th_flags & TH_PUSH) != 0;
            info->tcp_info.ack = (tcp_header->th_flags & TH_ACK) != 0;
            info->tcp_info.urg = (tcp_header->th_flags & TH_URG) != 0;
            
            // Sequence numbers
            info->tcp_info.seq = ntohl(tcp_header->th_seq);
            info->tcp_info.ack_seq = ntohl(tcp_header->th_ack);
            info->tcp_info.window = ntohs(tcp_header->th_win);
            break;
        }
        
        case IPPROTO_UDP: {
            const struct udphdr *udp_header = (struct udphdr *)((u_char *)ip_header + ip_header_size);
            info->src_port = ntohs(udp_header->uh_sport);
            info->dst_port = ntohs(udp_header->uh_dport);
            break;
        }
        
        case IPPROTO_ICMP:
            // ICMP doesn't have ports, but we could parse ICMP type and code here
            info->src_port = 0;
            info->dst_port = 0;
            break;
            
        default:
            info->src_port = 0;
            info->dst_port = 0;
            break;
    }
    
    return info;
}

void print_packet_info(const packet_info_t *info) {
    if (!info) return;
    
    char time_str[64];
    struct tm *tm_info = localtime(&info->timestamp.tv_sec);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
    
    printf("------------------------\n");
    printf("Time: %s.%06ld\n", time_str, info->timestamp.tv_usec);
    printf("Protocol: ");
    
    switch (info->protocol) {
        case IPPROTO_TCP:
            printf("TCP");
            break;
        case IPPROTO_UDP:
            printf("UDP");
            break;
        case IPPROTO_ICMP:
            printf("ICMP");
            break;
        default:
            printf("Other (%d)", info->protocol);
            break;
    }
    printf("\n");
    
    printf("Source IP: %s:%d\n", info->src_ip, info->src_port);
    printf("Dest   IP: %s:%d\n", info->dst_ip, info->dst_port);
    printf("Length: %u bytes\n", info->length);
    printf("TTL: %u\n", info->ttl);
    
    if (info->protocol == IPPROTO_TCP) {
        printf("TCP Flags: %s%s%s%s%s%s\n",
               info->tcp_info.fin ? "FIN " : "",
               info->tcp_info.syn ? "SYN " : "",
               info->tcp_info.rst ? "RST " : "",
               info->tcp_info.psh ? "PSH " : "",
               info->tcp_info.ack ? "ACK " : "",
               info->tcp_info.urg ? "URG " : "");
        printf("Seq: %u, Ack: %u, Window: %u\n", 
               info->tcp_info.seq, 
               info->tcp_info.ack_seq, 
               info->tcp_info.window);
    }
    
    printf("------------------------\n");
}

void free_packet_info(packet_info_t *info) {
    free(info);
}