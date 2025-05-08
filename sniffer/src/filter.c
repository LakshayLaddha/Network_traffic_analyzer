#include "../include/filter.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Array to store filter rules
static packet_filter_t *filter_rules = NULL;
static int filter_count = 0;
static int filter_capacity = 0;
static pthread_mutex_t filter_mutex = PTHREAD_MUTEX_INITIALIZER;

// Initialize filter subsystem
void initialize_filter(void) {
    pthread_mutex_lock(&filter_mutex);

    // Allocate initial space for filter rules
    filter_capacity = 10;
    filter_rules = (packet_filter_t *)malloc(filter_capacity * sizeof(packet_filter_t));
    if (filter_rules == NULL) {
        filter_capacity = 0;
    }
    filter_count = 0;

    pthread_mutex_unlock(&filter_mutex);
}

// Add a new filter rule
status_code_t add_filter_rule(const packet_filter_t *rule) {
    if (rule == NULL) {
        return STATUS_FAILURE;
    }

    pthread_mutex_lock(&filter_mutex);

    // Check if we need to resize the array
    if (filter_count >= filter_capacity) {
        int new_capacity = filter_capacity * 2;
        packet_filter_t *new_rules = (packet_filter_t *)realloc(filter_rules, new_capacity * sizeof(packet_filter_t));
        if (new_rules == NULL) {
            pthread_mutex_unlock(&filter_mutex);
            return STATUS_MEMORY_ERROR;
        }

        filter_rules = new_rules;
        filter_capacity = new_capacity;
    }

    // Add the new rule
    memcpy(&filter_rules[filter_count], rule, sizeof(packet_filter_t));
    filter_count++;

    pthread_mutex_unlock(&filter_mutex);
    return STATUS_SUCCESS;
}

// Apply filters to a packet, return true if packet should be processed
bool apply_filters(const packet_info_t *packet) {
    if (packet == NULL) {
        return false;
    }

    // If no filters, allow all packets
    if (filter_count == 0) {
        return true;
    }

    pthread_mutex_lock(&filter_mutex);

    bool allow_packet = true; // Default to allow if no matching rules

    for (int i = 0; i < filter_count; i++) {
        bool match = true;

        // Check if the source IP matches (if specified)
        if (filter_rules[i].src_ip[0] != '\0') {
            if (strcmp(packet->src_ip, filter_rules[i].src_ip) != 0) {
                match = false;
            }
        }

        // Check if the destination IP matches (if specified)
        if (match && filter_rules[i].dst_ip[0] != '\0') {
            if (strcmp(packet->dst_ip, filter_rules[i].dst_ip) != 0) {
                match = false;
            }
        }

        // Check if the source port matches (if specified)
        if (match && filter_rules[i].src_port != 0) {
            if (packet->src_port != filter_rules[i].src_port) {
                match = false;
            }
        }

        // Check if the destination port matches (if specified)
        if (match && filter_rules[i].dst_port != 0) {
            if (packet->dst_port != filter_rules[i].dst_port) {
                match = false;
            }
        }

        // Check if the protocol matches (if specified)
        if (match && filter_rules[i].protocol != 0) {
            if (packet->protocol != filter_rules[i].protocol) {
                match = false;
            }
        }

        // If all conditions match, apply the rule action
        if (match) {
            allow_packet = (filter_rules[i].action == FILTER_ALLOW);
            break; // Stop at the first matching rule
        }
    }

    pthread_mutex_unlock(&filter_mutex);
    return allow_packet;
}

// Load filter rules from a file
status_code_t load_filters_from_file(const char *filename) {
    if (filename == NULL) {
        return STATUS_FAILURE;
    }

    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        return STATUS_FAILURE;
    }

    char line[256];
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    unsigned int src_port, dst_port;
    unsigned int protocol;
    char action[10];

    // Clear existing filters
    pthread_mutex_lock(&filter_mutex);
    filter_count = 0;
    pthread_mutex_unlock(&filter_mutex);

    while (fgets(line, sizeof(line), file)) {
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') {
            continue;
        }

        // Parse the line
        src_ip[0] = dst_ip[0] = action[0] = '\0';
        src_port = dst_port = protocol = 0;

        if (sscanf(line, "%s %s %u %u %u %s", src_ip, dst_ip, &src_port, &dst_port, &protocol, action) < 1) {
            continue;
        }

        packet_filter_t rule;
        memset(&rule, 0, sizeof(rule));

        // Handle wildcard "*" as empty string for IPs
        if (strcmp(src_ip, "*") != 0) {
            strncpy(rule.src_ip, src_ip, INET_ADDRSTRLEN);
        }

        if (strcmp(dst_ip, "*") != 0) {
            strncpy(rule.dst_ip, dst_ip, INET_ADDRSTRLEN);
        }

        rule.src_port = src_port;
        rule.dst_port = dst_port;
        rule.protocol = (uint8_t)protocol;

        if (strcmp(action, "allow") == 0) {
            rule.action = FILTER_ALLOW;
        } else if (strcmp(action, "block") == 0) {
            rule.action = FILTER_BLOCK;
        } else {
            // Default to allow
            rule.action = FILTER_ALLOW;
        }

        // Add the rule
        add_filter_rule(&rule);
    }

    fclose(file);
    return STATUS_SUCCESS;
}

// Save filter rules to a file
status_code_t save_filters_to_file(const char *filename) {
    if (filename == NULL) {
        return STATUS_FAILURE;
    }

    FILE *file = fopen(filename, "w");
    if (file == NULL) {
        return STATUS_FAILURE;
    }

    // Write header
    fprintf(file, "# Filter rules format: <src_ip> <dst_ip> <src_port> <dst_port> <protocol> <action>\n");
    fprintf(file, "# Use * for wildcard IP addresses, and 0 for wildcard ports/protocol\n");

    pthread_mutex_lock(&filter_mutex);

    // Declare line buffer
    char line_buffer[32]; // Sufficient size for integers or strings

    for (int i = 0; i < filter_count; i++) {
        fprintf(file, "%s %s %s %s %u %s\n",
                filter_rules[i].src_ip[0] ? filter_rules[i].src_ip : "*",
                filter_rules[i].dst_ip[0] ? filter_rules[i].dst_ip : "*",
                (sprintf(line_buffer, "%d", filter_rules[i].src_port), line_buffer),
                (sprintf(line_buffer, "%d", filter_rules[i].dst_port), line_buffer),
                filter_rules[i].protocol,
                filter_rules[i].action == FILTER_ALLOW ? "allow" : "block");
    }

    pthread_mutex_unlock(&filter_mutex);

    fclose(file);
    return STATUS_SUCCESS;
}

// Clear all filter rules
void clear_filters(void) {
    pthread_mutex_lock(&filter_mutex);
    filter_count = 0;
    pthread_mutex_unlock(&filter_mutex);
}