#include "../include/common.h"
#include "../include/capture.h"
#include "../include/parser.h"
#include "../include/filter.h"
#include "../include/anomaly.h"
#include "../include/logger.h"
#include "../include/thread_pool.h"
#include <signal.h>
#include <getopt.h>
#include <stdio.h>

// Global variables
static volatile int running = 1;
static thread_pool_t thread_pool;
static capture_session_t capture_session;
static char output_file[256] = "stdout";
static log_format_t log_format = LOG_FORMAT_TEXT;
static log_level_t log_level = LOG_LEVEL_INFO;

// Function prototypes
static void handle_signal(int sig);
static void print_usage(const char *program_name);
static void process_packet(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet);
static void packet_processor(void *arg);  // Define this function later

// Signal handler
static void handle_signal(int sig) {
    printf("Signal received: %d\n", sig);
    running = 0;
}

// Print command line usage
static void print_usage(const char *program_name) {
    printf("Usage: %s [OPTIONS]\n\n", program_name);
    printf("Options:\n");
    printf("  -i, --interface <iface>    Network interface to capture packets from\n");
    printf("  -f, --filter <expr>        BPF filter expression\n");
    printf("  -o, --output <file>        Output file (default: stdout)\n");
    printf("  -j, --json                 Output in JSON format (default: text)\n");
    printf("  -v, --verbose              Increase verbosity (can be used multiple times)\n");
    printf("  -l, --list-interfaces      List available network interfaces\n");
    printf("  -r, --rules <file>         Load filter rules from file\n");
    printf("  -t, --threads <count>      Number of worker threads (default: 4)\n");
    printf("  -h, --help                 Display this help message and exit\n");
}

// Packet handler wrapper for pcap_loop
static void process_packet(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // Make a copy of the packet data for the worker thread
    u_char *packet_copy = (u_char *)malloc(pkthdr->caplen);
    if (!packet_copy) {
        log_message(LOG_LEVEL_ERROR, "Failed to allocate memory for packet copy");
        return;
    }
    memcpy(packet_copy, packet, pkthdr->caplen);

    // Make a copy of the packet header
    struct pcap_pkthdr *pkthdr_copy = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));
    if (!pkthdr_copy) {
        free(packet_copy);
        log_message(LOG_LEVEL_ERROR, "Failed to allocate memory for packet header copy");
        return;
    }
    memcpy(pkthdr_copy, pkthdr, sizeof(struct pcap_pkthdr));

    // Create a task argument containing the packet data and header
    struct {
        u_char *user;
        struct pcap_pkthdr *pkthdr;
        u_char *packet;
    } *task_arg = malloc(sizeof(*task_arg));

    if (!task_arg) {
        free(packet_copy);
        free(pkthdr_copy);
        log_message(LOG_LEVEL_ERROR, "Failed to allocate memory for task argument");
        return;
    }

    task_arg->user = user;  // This contains the datalink type
    task_arg->pkthdr = pkthdr_copy;
    task_arg->packet = packet_copy;

    // Submit the packet processing task to the thread pool
    if (thread_pool_add_task(&thread_pool, packet_processor, task_arg) != STATUS_SUCCESS) {
        free(packet_copy);
        free(pkthdr_copy);
        free(task_arg);
        log_message(LOG_LEVEL_ERROR, "Failed to add packet processing task to thread pool");
    }
}

// Worker thread function to process packets
static void packet_processor(void *arg) {
    struct {
        u_char *user;
        struct pcap_pkthdr *pkthdr;
        u_char *packet;
    } *task_arg = (void *)arg;

    // Parse the packet
    int datalink_type = *(int *)(task_arg->user);
    packet_info_t *packet_info = parse_packet(task_arg->pkthdr, task_arg->packet, datalink_type);

    if (packet_info) {
        // Apply custom filters
        if (apply_filters(packet_info)) {
            // Log the packet
            log_packet(packet_info);

            // Check for anomalies
            anomaly_info_t *anomaly = detect_anomalies(packet_info);
            if (anomaly) {
                log_anomaly(anomaly);
                free_anomaly_info(anomaly);
            }
        }

        free_packet_info(packet_info);
    }

    // Free the memory allocated for the task
    free(task_arg->pkthdr);
    free(task_arg->packet);
    free(task_arg);
}

int main(int argc, char *argv[]) {
    char *interface = NULL;
    char *filter_expr = NULL;
    char *rules_file = NULL;
    int num_threads = MAX_THREADS;
    int verbose_level = 0;

    // Command line option parsing
    static struct option long_options[] = {
        {"interface", required_argument, 0, 'i'},
        {"filter", required_argument, 0, 'f'},
        {"output", required_argument, 0, 'o'},
        {"json", no_argument, 0, 'j'},
        {"verbose", no_argument, 0, 'v'},
        {"list-interfaces", no_argument, 0, 'l'},
        {"rules", required_argument, 0, 'r'},
        {"threads", required_argument, 0, 't'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int c;
    int option_index = 0;

    while ((c = getopt_long(argc, argv, "i:f:o:jvlr:t:h", long_options, &option_index)) != -1) {
        switch (c) {
            case 'i':
                interface = optarg;
                break;

            case 'f':
                filter_expr = optarg;
                break;

            case 'o':
                strncpy(output_file, optarg, sizeof(output_file) - 1);
                output_file[sizeof(output_file) - 1] = '\0';
                break;

            case 'j':
                log_format = LOG_FORMAT_JSON;
                break;

            case 'v':
                verbose_level++;
                break;

            case 'l':
                get_device_list();
                return 0;

            case 'r':
                rules_file = optarg;
                break;

            case 't':
                num_threads = atoi(optarg);
                if (num_threads <= 0) {
                    num_threads = 1;
                } else if (num_threads > 32) {
                    num_threads = 32;  // Limit to sensible maximum
                }
                break;

            case 'h':
                print_usage(argv[0]);
                return 0;

            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    // Set log level based on verbosity
    if (verbose_level >= 3) {
        log_level = LOG_LEVEL_DEBUG;
    } else if (verbose_level == 2) {
        log_level = LOG_LEVEL_INFO;
    } else if (verbose_level == 1) {
        log_level = LOG_LEVEL_WARNING;
    } else {
        log_level = LOG_LEVEL_ERROR;
    }

    // Initialize logger
    if (initialize_logger(output_file, log_format, log_level) != STATUS_SUCCESS) {
        fprintf(stderr, "Failed to initialize logger with output file: %s\n", output_file);
        return 1;
    }

    log_message(LOG_LEVEL_INFO, "Network Traffic Analyzer starting up");

    // Initialize filter subsystem
    initialize_filter();

    // Load filter rules if specified
    if (rules_file) {
        if (load_filters_from_file(rules_file) != STATUS_SUCCESS) {
            log_message(LOG_LEVEL_ERROR, "Failed to load filter rules from file: %s", rules_file);
        } else {
            log_message(LOG_LEVEL_INFO, "Loaded filter rules from file: %s", rules_file);
        }
    }

    // Initialize anomaly detector
    initialize_anomaly_detector();

    // Initialize thread pool
    if (thread_pool_create(&thread_pool, num_threads, 1000) != STATUS_SUCCESS) {
        log_message(LOG_LEVEL_ERROR, "Failed to create thread pool");
        cleanup_logger();
        return 1;
    }

    log_message(LOG_LEVEL_INFO, "Created thread pool with %d worker threads", num_threads);

    // Initialize capture session
    memset(&capture_session, 0, sizeof(capture_session));
    capture_session.device = interface;
    capture_session.promiscuous = true;
    capture_session.snaplen = DEFAULT_SNAPLEN;
    capture_session.timeout = DEFAULT_TIMEOUT;

    if (initialize_capture(&capture_session) != STATUS_SUCCESS) {
        log_message(LOG_LEVEL_ERROR, "Failed to initialize packet capture");
        thread_pool_destroy(&thread_pool);
        cleanup_logger();
        return 1;
    }

    // Set up signal handlers for graceful termination
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    // Set packet filter if specified
    if (filter_expr) {
        if (set_filter(&capture_session, filter_expr) != STATUS_SUCCESS) {
            log_message(LOG_LEVEL_ERROR, "Failed to set packet filter: %s", filter_expr);
        } else {
            log_message(LOG_LEVEL_INFO, "Set packet filter: %s", filter_expr);
        }
    }

    // Create a static variable to hold the datalink type
    // This will be passed to the packet handler through the 'user' parameter
    static int datalink_type;
    datalink_type = capture_session.datalink_type;

    // Start capturing packets
    log_message(LOG_LEVEL_INFO, "Starting packet capture on interface: %s",
                capture_session.device ? capture_session.device : "default");

    if (start_capture(&capture_session, process_packet, (u_char *)&datalink_type) != STATUS_SUCCESS) {
        log_message(LOG_LEVEL_ERROR, "Packet capture failed");
    }

    log_message(LOG_LEVEL_INFO, "Packet capture stopped, waiting for pending tasks to complete");

    // Wait for all tasks to complete
    thread_pool_wait(&thread_pool);

    // Cleanup
    log_message(LOG_LEVEL_INFO, "Shutting down Network Traffic Analyzer");

    cleanup_capture(&capture_session);
    thread_pool_destroy(&thread_pool);
    cleanup_anomaly_detector();
    cleanup_logger();

    return 0;
}