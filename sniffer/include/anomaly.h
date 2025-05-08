#ifndef ANOMALY_H
#define ANOMALY_H

#include "common.h"
#include "parser.h"

typedef enum {
    ANOMALY_NONE = 0,
    ANOMALY_SYN_FLOOD,
    ANOMALY_PORT_SCAN,
    ANOMALY_UNUSUAL_PROTOCOL,
    ANOMALY_UNUSUAL_PACKET_SIZE,
    ANOMALY_INVALID_TCP_FLAGS
} anomaly_type_t;

typedef struct {
    anomaly_type_t type;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    uint16_t src_port;
    uint16_t dst_port;
    struct timeval timestamp;
    char description[256];
} anomaly_info_t;

// Function declarations
void initialize_anomaly_detector(void);
anomaly_info_t* detect_anomalies(const packet_info_t *packet);
void free_anomaly_info(anomaly_info_t *info);
void cleanup_anomaly_detector(void);

#endif // ANOMALY_H