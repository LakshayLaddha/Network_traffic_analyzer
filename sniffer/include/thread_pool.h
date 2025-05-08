#ifndef THREAD_POOL_H
#define THREAD_POOL_H

#include "common.h"
#include "parser.h"

typedef struct task_t task_t;
typedef void (*task_function_t)(void *arg);

// Thread pool structure
typedef struct {
    pthread_t *threads;               // Array of thread handles
    task_t *task_queue;               // Queue of tasks
    int queue_size;                   // Maximum number of tasks
    int head;                         // Head of the task queue
    int tail;                         // Tail of the task queue
    int count;                        // Number of pending tasks
    pthread_mutex_t queue_mutex;      // Mutex for queue access
    pthread_cond_t queue_not_empty;   // CV for signaling queue not empty
    pthread_cond_t queue_not_full;    // CV for signaling queue not full
    int num_threads;                  // Number of threads in the pool
    int active_threads;               // Number of active threads
    bool shutdown;                    // Shutdown flag
} thread_pool_t;

// Function declarations
status_code_t thread_pool_create(thread_pool_t *pool, int num_threads, int queue_size);
status_code_t thread_pool_add_task(thread_pool_t *pool, task_function_t function, void *arg);
status_code_t thread_pool_wait(thread_pool_t *pool);
void thread_pool_destroy(thread_pool_t *pool);

#endif // THREAD_POOL_H