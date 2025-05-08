#include <stdio.h>
#include "../include/capture.h"
#include "../include/parser.h"
#include "../include/logger.h"

static volatile int running = 1;

static void handle_signal(int sig) {
   printf("Signal received: %d\n", sig);
    running = 0;
}

status_code_t initialize_capture(capture_session_t *session) {
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    
    // Use default device if none specified
    if (session->device == NULL) {
        session->device = (char *)get_default_device();
        if (session->device == NULL) {
            fprintf(stderr, "Could not find default device: %s\n", errbuf);
            return STATUS_PCAP_ERROR;
        }
    }
    
    // Set defaults if not specified
    if (session->snaplen == 0) {
        session->snaplen = DEFAULT_SNAPLEN;
    }
    
    if (session->timeout == 0) {
        session->timeout = DEFAULT_TIMEOUT;
    }
    
    // Open pcap session
    session->handle = pcap_open_live(session->device, session->snaplen, 
                                     session->promiscuous, session->timeout, errbuf);
    if (session->handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", session->device, errbuf);
        return STATUS_PCAP_ERROR;
    }
    
    // Get datalink type
    session->datalink_type = pcap_datalink(session->handle);
    
    // Set up signal handler to gracefully terminate capture
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    
    return STATUS_SUCCESS;
}

status_code_t set_filter(capture_session_t *session, const char *filter_exp) {
    struct bpf_program fp;
    bpf_u_int32 net = 0;      // network address
    bpf_u_int32 mask = 0;     // network mask
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    
    // Get network address and mask
    if (pcap_lookupnet(session->device, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Could not get netmask for device %s: %s\n", session->device, errbuf);
        net = 0;
        mask = 0;
    }
    
    // Compile the filter expression
    if (pcap_compile(session->handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Could not parse filter %s: %s\n", filter_exp, pcap_geterr(session->handle));
        return STATUS_PCAP_ERROR;
    }
    
    // Set the filter
    if (pcap_setfilter(session->handle, &fp) == -1) {
        fprintf(stderr, "Could not install filter %s: %s\n", filter_exp, pcap_geterr(session->handle));
        pcap_freecode(&fp);
        return STATUS_PCAP_ERROR;
    }
    
    // Free the BPF program
    pcap_freecode(&fp);
    session->filter_exp = strdup(filter_exp);
    
    return STATUS_SUCCESS;
}

status_code_t start_capture(capture_session_t *session, pcap_handler callback, void *user) {
    int res;
    
    // Check if session is initialized
    if (session->handle == NULL) {
        fprintf(stderr, "Capture session not initialized\n");
        return STATUS_PCAP_ERROR;
    }

    log_message(LOG_LEVEL_INFO, "Starting packet capture on interface %s", session->device);
    if (session->filter_exp) {
        log_message(LOG_LEVEL_INFO, "Using filter: %s", session->filter_exp);
    }
    
    // Start packet processing loop
    while (running) {
        res = pcap_dispatch(session->handle, -1, callback, user);
        
        if (res == -1) {
            fprintf(stderr, "Error in pcap_dispatch: %s\n", pcap_geterr(session->handle));
            return STATUS_PCAP_ERROR;
        }
        
        // If we got interrupted, or no more packets
        if (res == -2 || !running) {
            break;
        }
        
        // Small delay to prevent CPU usage from spiking
        usleep(10000);  // 10ms
    }
    
    return STATUS_SUCCESS;
}

void cleanup_capture(capture_session_t *session) {
    if (session == NULL) return;
    
    if (session->handle) {
        pcap_close(session->handle);
        session->handle = NULL;
    }
    
    if (session->filter_exp) {
        free(session->filter_exp);
        session->filter_exp = NULL;
    }
}

const char *get_default_device(void) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *device __attribute__((unused));
    const char *default_device = NULL;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return NULL;
    }

    // Use the first device as the default
    if (alldevs != NULL) {
        default_device = alldevs->name;
    } else {
        fprintf(stderr, "No devices found.\n");
    }

    // Free the device list
    pcap_freealldevs(alldevs);
    return default_device;
}

void get_device_list(void) {
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_if_t *devices = NULL;
    pcap_if_t *dev;
    int i = 0;
    
    if (pcap_findalldevs(&devices, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return;
    }
    
    printf("Available network interfaces:\n");
    for (dev = devices; dev != NULL; dev = dev->next) {
        printf("%d. %s", ++i, dev->name);
        if (dev->description) {
            printf(" (%s)", dev->description);
        }
        printf("\n");
    }
    
    pcap_freealldevs(devices);
}