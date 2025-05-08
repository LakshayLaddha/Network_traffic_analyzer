#include "../include/anomaly.h"
#include "../include/logger.h"
#include <time.h>

// Data structures for anomaly detection
typedef struct {
    char ip[INET_ADDRSTRLEN];
    int syn_count;
    time_t first_syn;
    time_t last_update;
} syn_flood_tracker_t;

typedef struct {
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    uint16_t ports[65536/8]; // Bitmap for ports (1 bit per port)
    int port_count;
    time_t first_scan;
    time_t last_update;
} port_scan_tracker_t;

// Constants for anomaly detection
#define MAX_TRACKERS 1000
#define SYN_FLOOD_THRESHOLD 100  // # of SYNs in TIMEFRAME to trigger alert
#define SYN_FLOOD_TIMEFRAME 5    // seconds
#define PORT_SCAN_THRESHOLD 20   // # of ports in TIMEFRAME to trigger alert
#define PORT_SCAN_TIMEFRAME 5    // seconds
#define TRACKER_CLEANUP_INTERVAL 60 // seconds

// Static variables
static syn_flood_tracker_t syn_flood_trackers[MAX_TRACKERS];
static port_scan_tracker_t port_scan_trackers[MAX_TRACKERS];
static int syn_flood_tracker_count = 0;
static int port_scan_tracker_count = 0;
static pthread_mutex_t anomaly_mutex = PTHREAD_MUTEX_INITIALIZER;
static time_t last_cleanup = 0;

// Function prototypes
static anomaly_info_t* check_syn_flood(const packet_info_t *packet);
static anomaly_info_t* check_port_scan(const packet_info_t *packet);
static anomaly_info_t* check_tcp_flags(const packet_info_t *packet);
static anomaly_info_t* check_packet_size(const packet_info_t *packet);
static void cleanup_trackers(time_t now);

void initialize_anomaly_detector(void) {
    pthread_mutex_lock(&anomaly_mutex);
    
    // Initialize trackers
    memset(syn_flood_trackers, 0, sizeof(syn_flood_trackers));
    memset(port_scan_trackers, 0, sizeof(port_scan_trackers));
    syn_flood_tracker_count = 0;
    port_scan_tracker_count = 0;
    last_cleanup = time(NULL);
    
    pthread_mutex_unlock(&anomaly_mutex);
    
    log_message(LOG_LEVEL_INFO, "Anomaly detector initialized");
}

anomaly_info_t* detect_anomalies(const packet_info_t *packet) {
    if (!packet) return NULL;
    
    // Periodic cleanup of tracking data
    time_t now = time(NULL);
    if (now - last_cleanup > TRACKER_CLEANUP_INTERVAL) {
        cleanup_trackers(now);
        last_cleanup = now;
    }
    
    // Run different anomaly checks
    anomaly_info_t* anomaly = NULL;
    
    // Check for SYN flood (only for TCP packets with SYN flag)
    if (packet->protocol == IPPROTO_TCP && packet->tcp_info.syn) {
        anomaly = check_syn_flood(packet);
        if (anomaly) return anomaly;
    }
    
    // Check for port scanning
    anomaly = check_port_scan(packet);
    if (anomaly) return anomaly;
    
    // Check for invalid TCP flag combinations
    if (packet->protocol == IPPROTO_TCP) {
        anomaly = check_tcp_flags(packet);
        if (anomaly) return anomaly;
    }
    
    // Check for unusual packet sizes
    anomaly = check_packet_size(packet);
    if (anomaly) return anomaly;
    
    return NULL;  // No anomalies detected
}

static anomaly_info_t* check_syn_flood(const packet_info_t *packet) {
    pthread_mutex_lock(&anomaly_mutex);
    
    time_t now = time(NULL);
    int idx = -1;
    
    // Find existing tracker for this destination IP
    for (int i = 0; i < syn_flood_tracker_count; i++) {
        if (strcmp(syn_flood_trackers[i].ip, packet->dst_ip) == 0) {
            idx = i;
            break;
        }
    }
    
    // Create new tracker if not found
    if (idx == -1) {
        if (syn_flood_tracker_count < MAX_TRACKERS) {
            idx = syn_flood_tracker_count++;
            strncpy(syn_flood_trackers[idx].ip, packet->dst_ip, INET_ADDRSTRLEN);
            syn_flood_trackers[idx].syn_count = 0;
            syn_flood_trackers[idx].first_syn = now;
        } else {
            // No space for new tracker
            pthread_mutex_unlock(&anomaly_mutex);
            return NULL;
        }
    }
    
    // Update tracker
    syn_flood_trackers[idx].syn_count++;
    syn_flood_trackers[idx].last_update = now;
    
    // Check if threshold exceeded within timeframe
    anomaly_info_t* anomaly = NULL;
    if (syn_flood_trackers[idx].syn_count >= SYN_FLOOD_THRESHOLD && 
        (now - syn_flood_trackers[idx].first_syn <= SYN_FLOOD_TIMEFRAME)) {
        
        // Create anomaly record
        anomaly = (anomaly_info_t*)malloc(sizeof(anomaly_info_t));
        if (anomaly) {
            anomaly->type = ANOMALY_SYN_FLOOD;
            strncpy(anomaly->src_ip, packet->src_ip, INET_ADDRSTRLEN);
            strncpy(anomaly->dst_ip, packet->dst_ip, INET_ADDRSTRLEN);
            anomaly->src_port = packet->src_port;
            anomaly->dst_port = packet->dst_port;
            anomaly->timestamp = packet->timestamp;
            snprintf(anomaly->description, sizeof(anomaly->description),
                     "SYN flood detected: %d SYN packets in %ld seconds",
                     syn_flood_trackers[idx].syn_count,
                     now - syn_flood_trackers[idx].first_syn);
            
            // Reset the counter to avoid continuous alerts
            syn_flood_trackers[idx].syn_count = 0;
            syn_flood_trackers[idx].first_syn = now;
        }
    }
    
    pthread_mutex_unlock(&anomaly_mutex);
    return anomaly;
}

static anomaly_info_t* check_port_scan(const packet_info_t *packet) {
    if (packet->protocol != IPPROTO_TCP && packet->protocol != IPPROTO_UDP) {
        return NULL;
    }
    
    pthread_mutex_lock(&anomaly_mutex);
    
    time_t now = time(NULL);
    int idx = -1;
    
    // Find existing tracker for this source IP + destination IP combination
    for (int i = 0; i < port_scan_tracker_count; i++) {
        if (strcmp(port_scan_trackers[i].src_ip, packet->src_ip) == 0 &&
            strcmp(port_scan_trackers[i].dst_ip, packet->dst_ip) == 0) {
            idx = i;
            break;
        }
    }
    
    // Create new tracker if not found
    if (idx == -1) {
        if (port_scan_tracker_count < MAX_TRACKERS) {
            idx = port_scan_tracker_count++;
            strncpy(port_scan_trackers[idx].src_ip, packet->src_ip, INET_ADDRSTRLEN);
            strncpy(port_scan_trackers[idx].dst_ip, packet->dst_ip, INET_ADDRSTRLEN);
            memset(port_scan_trackers[idx].ports, 0, sizeof(port_scan_trackers[idx].ports));
            port_scan_trackers[idx].port_count = 0;
            port_scan_trackers[idx].first_scan = now;
        } else {
            // No space for new tracker
            pthread_mutex_unlock(&anomaly_mutex);
            return NULL;
        }
    }
    
    // Check if we've seen this port before
    int port_idx = packet->dst_port / 8;
    int port_bit = packet->dst_port % 8;
    
    if ((port_scan_trackers[idx].ports[port_idx] & (1 << port_bit)) == 0) {
        // New port
        port_scan_trackers[idx].ports[port_idx] |= (1 << port_bit);
        port_scan_trackers[idx].port_count++;
    }
    
    port_scan_trackers[idx].last_update = now;
    
    // Check if threshold exceeded within timeframe
    anomaly_info_t* anomaly = NULL;
    if (port_scan_trackers[idx].port_count >= PORT_SCAN_THRESHOLD && 
        (now - port_scan_trackers[idx].first_scan <= PORT_SCAN_TIMEFRAME)) {
        
        // Create anomaly record
        anomaly = (anomaly_info_t*)malloc(sizeof(anomaly_info_t));
        if (anomaly) {
            anomaly->type = ANOMALY_PORT_SCAN;
            strncpy(anomaly->src_ip, packet->src_ip, INET_ADDRSTRLEN);
            strncpy(anomaly->dst_ip, packet->dst_ip, INET_ADDRSTRLEN);
            anomaly->src_port = packet->src_port;
            anomaly->dst_port = packet->dst_port;
            anomaly->timestamp = packet->timestamp;
            snprintf(anomaly->description, sizeof(anomaly->description),
                     "Port scan detected: %d ports in %ld seconds",
                     port_scan_trackers[idx].port_count,
                     now - port_scan_trackers[idx].first_scan);
            
            // Reset the counter to avoid continuous alerts
            memset(port_scan_trackers[idx].ports, 0, sizeof(port_scan_trackers[idx].ports));
            port_scan_trackers[idx].port_count = 0;
            port_scan_trackers[idx].first_scan = now;
        }
    }
    
    pthread_mutex_unlock(&anomaly_mutex);
    return anomaly;
}

static anomaly_info_t* check_tcp_flags(const packet_info_t *packet) {
    if (packet->protocol != IPPROTO_TCP) {
        return NULL;
    }
    
    // Check for invalid flag combinations
    bool invalid_flags = false;
    char reason[100] = {0};
    
    // SYN+FIN is invalid (RFC 793)
    if (packet->tcp_info.syn && packet->tcp_info.fin) {
        invalid_flags = true;
        strcpy(reason, "Both SYN and FIN flags set");
    }
    // SYN+RST is invalid
    else if (packet->tcp_info.syn && packet->tcp_info.rst) {
        invalid_flags = true;
        strcpy(reason, "Both SYN and RST flags set");
    }
    // No flags set is invalid
    else if (!packet->tcp_info.syn && !packet->tcp_info.ack && !packet->tcp_info.fin && 
             !packet->tcp_info.rst && !packet->tcp_info.psh && !packet->tcp_info.urg) {
        invalid_flags = true;
        strcpy(reason, "No TCP flags set");
    }
    
    if (invalid_flags) {
        anomaly_info_t* anomaly = (anomaly_info_t*)malloc(sizeof(anomaly_info_t));
        if (anomaly) {
            anomaly->type = ANOMALY_INVALID_TCP_FLAGS;
            strncpy(anomaly->src_ip, packet->src_ip, INET_ADDRSTRLEN);
            strncpy(anomaly->dst_ip, packet->dst_ip, INET_ADDRSTRLEN);
            anomaly->src_port = packet->src_port;
            anomaly->dst_port = packet->dst_port;
            anomaly->timestamp = packet->timestamp;
            snprintf(anomaly->description, sizeof(anomaly->description),
                     "Invalid TCP flags: %s (Flags: %s%s%s%s%s%s)",
                     reason,
                     packet->tcp_info.fin ? "FIN " : "",
                     packet->tcp_info.syn ? "SYN " : "",
                     packet->tcp_info.rst ? "RST " : "",
                     packet->tcp_info.psh ? "PSH " : "",
                     packet->tcp_info.ack ? "ACK " : "",
                     packet->tcp_info.urg ? "URG " : "");
            return anomaly;
        }
    }
    
    return NULL;
}

static anomaly_info_t* check_packet_size(const packet_info_t *packet) {
    // Check for unusually large packets
    if (packet->length > 1500) {  // Most Ethernet MTUs are 1500
        anomaly_info_t* anomaly = (anomaly_info_t*)malloc(sizeof(anomaly_info_t));
        if (anomaly) {
            anomaly->type = ANOMALY_UNUSUAL_PACKET_SIZE;
            strncpy(anomaly->src_ip, packet->src_ip, INET_ADDRSTRLEN);
            strncpy(anomaly->dst_ip, packet->dst_ip, INET_ADDRSTRLEN);
            anomaly->src_port = packet->src_port;
            anomaly->dst_port = packet->dst_port;
            anomaly->timestamp = packet->timestamp;
            snprintf(anomaly->description, sizeof(anomaly->description),
                     "Unusually large packet: %d bytes", packet->length);
            return anomaly;
        }
    }
    
    // Check for tiny TCP packets (potential DoS attack)
    if (packet->protocol == IPPROTO_TCP && packet->length < 40) {
        anomaly_info_t* anomaly = (anomaly_info_t*)malloc(sizeof(anomaly_info_t));
        if (anomaly) {
            anomaly->type = ANOMALY_UNUSUAL_PACKET_SIZE;
            strncpy(anomaly->src_ip, packet->src_ip, INET_ADDRSTRLEN);
            strncpy(anomaly->dst_ip, packet->dst_ip, INET_ADDRSTRLEN);
            anomaly->src_port = packet->src_port;
            anomaly->dst_port = packet->dst_port;
            anomaly->timestamp = packet->timestamp;
            snprintf(anomaly->description, sizeof(anomaly->description),
                     "Unusually small TCP packet: %d bytes", packet->length);
            return anomaly;
        }
    }
    
    return NULL;
}

static void cleanup_trackers(time_t now) {
    pthread_mutex_lock(&anomaly_mutex);
    
    // Cleanup SYN flood trackers
    int i = 0;
    while (i < syn_flood_tracker_count) {
        if (now - syn_flood_trackers[i].last_update > 2 * SYN_FLOOD_TIMEFRAME) {
            // Remove this tracker by replacing it with the last one
            if (i < syn_flood_tracker_count - 1) {
                memcpy(&syn_flood_trackers[i], &syn_flood_trackers[syn_flood_tracker_count-1], 
                       sizeof(syn_flood_tracker_t));
            }
            syn_flood_tracker_count--;
        } else {
            i++;
        }
    }
    
    // Cleanup port scan trackers
    i = 0;
    while (i < port_scan_tracker_count) {
        if (now - port_scan_trackers[i].last_update > 2 * PORT_SCAN_TIMEFRAME) {
            // Remove this tracker by replacing it with the last one
            if (i < port_scan_tracker_count - 1) {
                memcpy(&port_scan_trackers[i], &port_scan_trackers[port_scan_tracker_count-1], 
                       sizeof(port_scan_tracker_t));
            }
            port_scan_tracker_count--;
        } else {
            i++;
        }
    }
    
    pthread_mutex_unlock(&anomaly_mutex);
}

void free_anomaly_info(anomaly_info_t *info) {
    free(info);
}

void cleanup_anomaly_detector(void) {
    pthread_mutex_lock(&anomaly_mutex);
    
    // Reset all trackers
    memset(syn_flood_trackers, 0, sizeof(syn_flood_trackers));
    memset(port_scan_trackers, 0, sizeof(port_scan_trackers));
    syn_flood_tracker_count = 0;
    port_scan_tracker_count = 0;
    
    pthread_mutex_unlock(&anomaly_mutex);
}