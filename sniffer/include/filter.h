#ifndef FILTER_H
#define FILTER_H

#include "common.h"
#include "parser.h"

typedef enum {
    FILTER_ALLOW,
    FILTER_BLOCK
} filter_action_t;

typedef struct {
    char src_ip[INET_ADDRSTRLEN];    // Source IP to filter (empty for any)
    char dst_ip[INET_ADDRSTRLEN];    // Destination IP to filter (empty for any) 
    uint16_t src_port;               // Source port to filter (0 for any)
    uint16_t dst_port;               // Destination port to filter (0 for any)
    uint8_t protocol;                // Protocol to filter (0 for any)
    filter_action_t action;          // Allow or block
} packet_filter_t;

// Function declarations
void initialize_filter(void);
status_code_t add_filter_rule(const packet_filter_t *rule);
bool apply_filters(const packet_info_t *packet);
status_code_t load_filters_from_file(const char *filename);
status_code_t save_filters_to_file(const char *filename);
void clear_filters(void);

#endif // FILTER_H