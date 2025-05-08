#include "../include/logger.h"
#include <stdarg.h>
#include <time.h>

// Logger state
static FILE *log_file = NULL;
static log_format_t log_format = LOG_FORMAT_TEXT;
static log_level_t current_log_level = LOG_LEVEL_INFO;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

// Internal functions
static const char* log_level_to_string(log_level_t level) {
    switch (level) {
        case LOG_LEVEL_ERROR: return "ERROR";
        case LOG_LEVEL_WARNING: return "WARNING";
        case LOG_LEVEL_INFO: return "INFO";
        case LOG_LEVEL_DEBUG: return "DEBUG";
        default: return "UNKNOWN";
    }
}

static void get_timestamp_str(char *buffer, size_t size) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", tm_info);
}

status_code_t initialize_logger(const char *log_path, log_format_t format, log_level_t level) {
    pthread_mutex_lock(&log_mutex);
    
    // Close any existing log file
    if (log_file != NULL && log_file != stdout) {
        fclose(log_file);
    }
    
    // Open the log file
    if (log_path == NULL || strcmp(log_path, "stdout") == 0) {
        log_file = stdout;
    } else {
        log_file = fopen(log_path, "a");
        if (log_file == NULL) {
            pthread_mutex_unlock(&log_mutex);
            return STATUS_FAILURE;
        }
    }
    
    // Set the log format and level
    log_format = format;
    current_log_level = level;
    
    // Write header if using JSON format
    if (log_format == LOG_FORMAT_JSON && log_file != stdout) {
        fprintf(log_file, "[\n");
    }
    
    pthread_mutex_unlock(&log_mutex);
    return STATUS_SUCCESS;
}

status_code_t log_message(log_level_t level, const char *format, ...) {
    if (level > current_log_level) {
        return STATUS_SUCCESS;  // Skip logging if level is higher than current
    }
    
    if (log_file == NULL) {
        return STATUS_FAILURE;
    }
    
    pthread_mutex_lock(&log_mutex);
    
    va_list args;
    char timestamp[64];
    get_timestamp_str(timestamp, sizeof(timestamp));
    
    if (log_format == LOG_FORMAT_TEXT) {
        fprintf(log_file, "[%s] [%s] ", timestamp, log_level_to_string(level));
        va_start(args, format);
        vfprintf(log_file, format, args);
        va_end(args);
        fprintf(log_file, "\n");
    } else if (log_format == LOG_FORMAT_JSON) {
        fprintf(log_file, "{\"timestamp\":\"%s\",\"level\":\"%s\",\"message\":\"", 
                timestamp, log_level_to_string(level));
        
        // Need to escape special characters for JSON
        va_start(args, format);
        char message[1024];
        vsnprintf(message, sizeof(message), format, args);
        va_end(args);
        
        // Basic escaping for JSON
        char *p = message;
        while (*p) {
            switch (*p) {
                case '\\': fprintf(log_file, "\\\\"); break;
                case '\"': fprintf(log_file, "\\\""); break;
                case '\n': fprintf(log_file, "\\n"); break;
                case '\r': fprintf(log_file, "\\r"); break;
                case '\t': fprintf(log_file, "\\t"); break;
                default: fputc(*p, log_file);
            }
            p++;
        }
        
        fprintf(log_file, "\"}\n");
    }
    
    fflush(log_file);
    pthread_mutex_unlock(&log_mutex);
    
    return STATUS_SUCCESS;
}

status_code_t log_packet(const packet_info_t *packet) {
    if (!packet || !log_file) {
        return STATUS_FAILURE;
    }
    
    pthread_mutex_lock(&log_mutex);
    
    char timestamp[64];
    struct tm *tm_info = localtime(&packet->timestamp.tv_sec);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    if (log_format == LOG_FORMAT_TEXT) {
        fprintf(log_file, "[%s.%06ld] PACKET %s:%d -> %s:%d %s %d bytes\n",
                timestamp, 
                packet->timestamp.tv_usec,
                packet->src_ip, 
                packet->src_port,
                packet->dst_ip, 
                packet->dst_port,
                packet->protocol == IPPROTO_TCP ? "TCP" : 
                packet->protocol == IPPROTO_UDP ? "UDP" : 
                packet->protocol == IPPROTO_ICMP ? "ICMP" : "OTHER",
                packet->length);
    } else if (log_format == LOG_FORMAT_JSON) {
        fprintf(log_file, 
                "{\"type\":\"packet\",\"timestamp\":\"%s.%06ld\","
                "\"src_ip\":\"%s\",\"src_port\":%d,"
                "\"dst_ip\":\"%s\",\"dst_port\":%d,"
                "\"protocol\":\"%s\",\"length\":%d",
                timestamp, 
                packet->timestamp.tv_usec,
                packet->src_ip, 
                packet->src_port,
                packet->dst_ip, 
                packet->dst_port,
                packet->protocol == IPPROTO_TCP ? "TCP" : 
                packet->protocol == IPPROTO_UDP ? "UDP" : 
                packet->protocol == IPPROTO_ICMP ? "ICMP" : "OTHER",
                packet->length);
        
        // Add TCP specific fields if applicable
        if (packet->protocol == IPPROTO_TCP) {
            fprintf(log_file, 
                    ",\"tcp_flags\":{"
                    "\"fin\":%s,\"syn\":%s,\"rst\":%s,"
                    "\"psh\":%s,\"ack\":%s,\"urg\":%s},"
                    "\"tcp_seq\":%u,\"tcp_ack\":%u,\"tcp_win\":%u",
                    packet->tcp_info.fin ? "true" : "false",
                    packet->tcp_info.syn ? "true" : "false",
                    packet->tcp_info.rst ? "true" : "false",
                    packet->tcp_info.psh ? "true" : "false",
                    packet->tcp_info.ack ? "true" : "false",
                    packet->tcp_info.urg ? "true" : "false",
                    packet->tcp_info.seq,
                    packet->tcp_info.ack_seq,
                    packet->tcp_info.window);
        }
        
        fprintf(log_file, "}\n");
    }
    
    fflush(log_file);
    pthread_mutex_unlock(&log_mutex);
    
    return STATUS_SUCCESS;
}

status_code_t log_anomaly(const anomaly_info_t *anomaly) {
    if (!anomaly || !log_file) {
        return STATUS_FAILURE;
    }
    
    pthread_mutex_lock(&log_mutex);
    
    char timestamp[64];
    struct tm *tm_info = localtime(&anomaly->timestamp.tv_sec);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    const char *anomaly_type = "";
    switch (anomaly->type) {
        case ANOMALY_SYN_FLOOD: anomaly_type = "SYN_FLOOD"; break;
        case ANOMALY_PORT_SCAN: anomaly_type = "PORT_SCAN"; break;
        case ANOMALY_UNUSUAL_PROTOCOL: anomaly_type = "UNUSUAL_PROTOCOL"; break;
        case ANOMALY_UNUSUAL_PACKET_SIZE: anomaly_type = "UNUSUAL_PACKET_SIZE"; break;
        case ANOMALY_INVALID_TCP_FLAGS: anomaly_type = "INVALID_TCP_FLAGS"; break;
        default: anomaly_type = "UNKNOWN"; break;
    }
    
    if (log_format == LOG_FORMAT_TEXT) {
        fprintf(log_file, "[%s.%06ld] ANOMALY [%s] %s:%d -> %s:%d %s\n",
                timestamp, 
                anomaly->timestamp.tv_usec,
                anomaly_type,
                anomaly->src_ip, 
                anomaly->src_port,
                anomaly->dst_ip, 
                anomaly->dst_port,
                anomaly->description);
    } else if (log_format == LOG_FORMAT_JSON) {
        fprintf(log_file, 
                "{\"type\":\"anomaly\",\"timestamp\":\"%s.%06ld\","
                "\"anomaly_type\":\"%s\","
                "\"src_ip\":\"%s\",\"src_port\":%d,"
                "\"dst_ip\":\"%s\",\"dst_port\":%d,"
                "\"description\":\"%s\"}\n",
                timestamp, 
                anomaly->timestamp.tv_usec,
                anomaly_type,
                anomaly->src_ip, 
                anomaly->src_port,
                anomaly->dst_ip, 
                anomaly->dst_port,
                anomaly->description);
    }
    
    fflush(log_file);
    pthread_mutex_unlock(&log_mutex);
    
    return STATUS_SUCCESS;
}

void cleanup_logger(void) {
    pthread_mutex_lock(&log_mutex);
    
    if (log_file != NULL && log_file != stdout) {
        // If JSON format, close the array
        if (log_format == LOG_FORMAT_JSON) {
            fprintf(log_file, "]\n");
        }
        
        fclose(log_file);
        log_file = NULL;
    }
    
    pthread_mutex_unlock(&log_mutex);
}