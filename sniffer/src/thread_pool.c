#include "../include/thread_pool.h"

// Task structure
struct task_t {
    task_function_t function;
    void *arg;
};

// Thread function
static void *worker_thread(void *arg) {
    thread_pool_t *pool = (thread_pool_t *)arg;
    task_t task;
    
    while (1) {
        // Lock the queue mutex
        pthread_mutex_lock(&pool->queue_mutex);
        
        // Wait for a task
        while (pool->count == 0 && !pool->shutdown) {
            pthread_cond_wait(&pool->queue_not_empty, &pool->queue_mutex);
        }
        
        // Check if we need to shutdown
        if (pool->shutdown) {
            pthread_mutex_unlock(&pool->queue_mutex);
            pthread_exit(NULL);
        }
        
        // Get a task from the queue
        task.function = pool->task_queue[pool->head].function;
        task.arg = pool->task_queue[pool->head].arg;
        
        pool->head = (pool->head + 1) % pool->queue_size;
        pool->count--;
        
        // Signal that the queue is not full
        pthread_cond_signal(&pool->queue_not_full);
        
        // Increment active threads
        pool->active_threads++;
        
        // Unlock the queue mutex
        pthread_mutex_unlock(&pool->queue_mutex);
        
        // Execute the task
        (*(task.function))(task.arg);
        
        // Decrement active threads
        pthread_mutex_lock(&pool->queue_mutex);
        pool->active_threads--;
        
        // If we're waiting for completion and this is the last thread
        if (pool->active_threads == 0 && pool->count == 0) {
            pthread_cond_broadcast(&pool->queue_not_empty);
        }
        
        pthread_mutex_unlock(&pool->queue_mutex);
    }
    
    return NULL;
}

status_code_t thread_pool_create(thread_pool_t *pool, int num_threads, int queue_size) {
    if (!pool || num_threads <= 0 || queue_size <= 0) {
        return STATUS_FAILURE;
    }
    
    // Initialize the pool
    pool->threads = (pthread_t *)malloc(sizeof(pthread_t) * num_threads);
    if (!pool->threads) {
        return STATUS_MEMORY_ERROR;
    }
    
    pool->task_queue = (task_t *)malloc(sizeof(task_t) * queue_size);
    if (!pool->task_queue) {
        free(pool->threads);
        return STATUS_MEMORY_ERROR;
    }
    
    pool->queue_size = queue_size;
    pool->head = 0;
    pool->tail = 0;
    pool->count = 0;
    pool->num_threads = num_threads;
    pool->active_threads = 0;
    pool->shutdown = false;
    
    // Initialize mutex and condition variables
    if (pthread_mutex_init(&pool->queue_mutex, NULL) != 0 ||
        pthread_cond_init(&pool->queue_not_empty, NULL) != 0 ||
        pthread_cond_init(&pool->queue_not_full, NULL) != 0) {
        
        free(pool->threads);
        free(pool->task_queue);
        return STATUS_THREAD_ERROR;
    }
    
    // Create worker threads
    for (int i = 0; i < num_threads; i++) {
        if (pthread_create(&pool->threads[i], NULL, worker_thread, pool) != 0) {
            thread_pool_destroy(pool);
            return STATUS_THREAD_ERROR;
        }
    }
    
    return STATUS_SUCCESS;
}

status_code_t thread_pool_add_task(thread_pool_t *pool, task_function_t function, void *arg) {
    if (!pool || !function) {
        return STATUS_FAILURE;
    }
    
    // Lock the queue mutex
    pthread_mutex_lock(&pool->queue_mutex);
    
    // Wait if the queue is full
    while (pool->count == pool->queue_size && !pool->shutdown) {
        pthread_cond_wait(&pool->queue_not_full, &pool->queue_mutex);
    }
    
    // Check if the pool is shutting down
    if (pool->shutdown) {
        pthread_mutex_unlock(&pool->queue_mutex);
        return STATUS_FAILURE;
    }
    
    // Add the task to the queue
    pool->task_queue[pool->tail].function = function;
    pool->task_queue[pool->tail].arg = arg;
    
    pool->tail = (pool->tail + 1) % pool->queue_size;
    pool->count++;
    
    // Signal that the queue is not empty
    pthread_cond_signal(&pool->queue_not_empty);
    
    // Unlock the queue mutex
    pthread_mutex_unlock(&pool->queue_mutex);
    
    return STATUS_SUCCESS;
}

status_code_t thread_pool_wait(thread_pool_t *pool) {
    if (!pool) {
        return STATUS_FAILURE;
    }
    
    // Lock the queue mutex
    pthread_mutex_lock(&pool->queue_mutex);
    
    // Wait until all tasks are complete and no active threads
    while (pool->count > 0 || pool->active_threads > 0) {
        pthread_cond_wait(&pool->queue_not_empty, &pool->queue_mutex);
    }
    
    // Unlock the queue mutex
    pthread_mutex_unlock(&pool->queue_mutex);
    
    return STATUS_SUCCESS;
}

void thread_pool_destroy(thread_pool_t *pool) {
    if (!pool) return;
    
    // Lock the queue mutex
    pthread_mutex_lock(&pool->queue_mutex);
    
    // Set the shutdown flag
    pool->shutdown = true;
    
    // Signal all worker threads to wake up
    pthread_cond_broadcast(&pool->queue_not_empty);
    pthread_cond_broadcast(&pool->queue_not_full);
    
    // Unlock the queue mutex
    pthread_mutex_unlock(&pool->queue_mutex);
    
    // Wait for all worker threads to exit
    for (int i = 0; i < pool->num_threads; i++) {
        pthread_join(pool->threads[i], NULL);
    }
    
    // Free resources
    free(pool->threads);
    free(pool->task_queue);
    
    // Destroy mutex and condition variables
    pthread_mutex_destroy(&pool->queue_mutex);
    pthread_cond_destroy(&pool->queue_not_empty);
    pthread_cond_destroy(&pool->queue_not_full);
}