#ifndef CAPTURE_H
#define CAPTURE_H

#include "common.h"

// Struct to hold capture session info
typedef struct {
    pcap_t *handle;          // Pcap handle
    char *device;            // Network interface name
    char *filter_exp;        // BPF filter expression
    int snaplen;             // Snapshot length
    int timeout;             // Read timeout in ms
    bool promiscuous;        // Promiscuous mode flag
    int datalink_type;       // Link layer header type
} capture_session_t;

// Function declarations
status_code_t initialize_capture(capture_session_t *session);
status_code_t start_capture(capture_session_t *session, pcap_handler callback, void *user);
status_code_t set_filter(capture_session_t *session, const char *filter_exp);
void cleanup_capture(capture_session_t *session);
void get_device_list(void);
const char *get_default_device(void);

#endif // CAPTURE_H