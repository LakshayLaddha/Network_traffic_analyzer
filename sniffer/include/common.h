#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <stdbool.h>

// Shared constants
#define MAX_PACKET_SIZE 65535
#define PACKET_BUFFER_SIZE 1000
#define MAX_THREADS 4
#define DEFAULT_SNAPLEN 65535
#define DEFAULT_TIMEOUT 1000 // in milliseconds

// Error handling macro
#define CHECK_NULL(x, msg) \
    if ((x) == NULL) { \
        fprintf(stderr, "%s\n", msg); \
        exit(EXIT_FAILURE); \
    }

// Status codes
typedef enum {
    STATUS_SUCCESS = 0,
    STATUS_FAILURE = -1,
    STATUS_MEMORY_ERROR = -2,
    STATUS_PCAP_ERROR = -3,
    STATUS_THREAD_ERROR = -4
} status_code_t;

#endif // COMMON_H