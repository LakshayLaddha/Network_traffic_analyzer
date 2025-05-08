#ifndef LOGGER_H
#define LOGGER_H

#include "common.h"
#include "parser.h"
#include "anomaly.h"

typedef enum {
    LOG_LEVEL_ERROR = 0,
    LOG_LEVEL_WARNING = 1,
    LOG_LEVEL_INFO = 2,
    LOG_LEVEL_DEBUG = 3
} log_level_t;

typedef enum {
    LOG_FORMAT_TEXT = 0,
    LOG_FORMAT_JSON = 1
} log_format_t;

// Function declarations
status_code_t initialize_logger(const char *log_path, log_format_t format, log_level_t level);
status_code_t log_packet(const packet_info_t *packet);
status_code_t log_anomaly(const anomaly_info_t *anomaly);
status_code_t log_message(log_level_t level, const char *format, ...);
void cleanup_logger(void);

#endif // LOGGER_H