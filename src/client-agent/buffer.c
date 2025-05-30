/*
 * Anti-flooding mechanism
 * Copyright (C) 2015, Wazuh Inc.
 * July 4, 2017
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
*/

#include <pthread.h>
#include "shared.h"
#include "agentd.h"

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#endif

#ifdef WAZUH_UNIT_TESTING
// Remove STATIC qualifier from tests
#define STATIC
#else
#define STATIC static
#endif

STATIC volatile int i = 0;
STATIC volatile int j = 0;
static volatile int state = NORMAL;

int warn_level;
int normal_level;
int tolerance;

struct{
  unsigned int full:1;
  unsigned int warn:1;
  unsigned int flood:1;
  unsigned int normal:1;
} buff;

static char ** buffer;
static pthread_mutex_t mutex_lock;
static pthread_cond_t cond_no_empty;

static time_t start, end;

/**
 * @brief Sleep according to max_eps parameter
 *
 * Sleep (1 / max_eps) - ts_loop
 *
 * @param ts_loop Loop time.
 */
static void delay(struct timespec * ts_loop);

/* Create agent buffer */
void buffer_init(){

    if (!buffer)
        os_calloc(agt->buflength+1, sizeof(char *), buffer);

    /* Read internal configuration */
    warn_level = getDefine_Int("agent", "warn_level", 1, 100);
    normal_level = getDefine_Int("agent", "normal_level", 0, warn_level-1);
    tolerance = getDefine_Int("agent", "tolerance", 0, 600);

    w_mutex_init(&mutex_lock, NULL);
    w_cond_init(&cond_no_empty, NULL);

    if (tolerance == 0)
        mwarn(TOLERANCE_TIME);

    mdebug1("Agent buffer created.");
}

/* Send messages to buffer. */
int buffer_append(const char *msg){

    w_mutex_lock(&mutex_lock);

    /* Check if buffer usage reaches any higher level */
    switch (state) {

        case NORMAL:
            if (full(i, j, agt->buflength + 1)){
                buff.full = 1;
                state = FULL;
                start = time(0);
            }else if (warn(i, j)){
                state = WARNING;
                buff.warn = 1;
            }
            break;

        case WARNING:
            if (full(i, j, agt->buflength + 1)){
                buff.full = 1;
                state = FULL;
                start = time(0);
            }
            break;

        case FULL:
            end = time(0);
            if (end - start >= tolerance){
                state = FLOOD;
                buff.flood = 1;
            }
            break;

        case FLOOD:
            break;
    }

    w_agentd_state_update(INCREMENT_MSG_COUNT, NULL);

    /* When buffer is full, event is dropped */

    if (full(i, j, agt->buflength + 1)){

        w_mutex_unlock(&mutex_lock);
        mdebug2("Unable to store new packet: Buffer is full.");
        return(-1);

    }else{

        buffer[i] = strdup(msg);
        forward(i, agt->buflength + 1);
        w_cond_signal(&cond_no_empty);
        w_mutex_unlock(&mutex_lock);

        return(0);
    }
}

/* Send messages from buffer to the server */
#ifdef WIN32
DWORD WINAPI dispatch_buffer(__attribute__((unused)) LPVOID arg) {
#else
void *dispatch_buffer(__attribute__((unused)) void * arg){
#endif
    char flood_msg[OS_MAXSTR];
    char full_msg[OS_MAXSTR];
    char warn_msg[OS_MAXSTR];
    char normal_msg[OS_MAXSTR];

    char warn_str[OS_SIZE_2048];
    struct timespec ts0;
    struct timespec ts1;

    while(1){
        gettime(&ts0);

        w_mutex_lock(&mutex_lock);

        while(empty(i, j)){
            w_cond_wait(&cond_no_empty, &mutex_lock);
        }
        /* Check if buffer usage reaches any lower level */
        switch (state) {

            case NORMAL:
                break;

            case WARNING:
                if (normal(i, j)){
                    state = NORMAL;
                    buff.normal = 1;
                }
                break;

            case FULL:
                if (nowarn(i, j))
                    state = WARNING;

                if (normal(i, j)){
                    state = NORMAL;
                    buff.normal = 1;
                }
                break;

            case FLOOD:
                if (nowarn(i, j))
                    state = WARNING;

                if (normal(i, j)){
                    state = NORMAL;
                    buff.normal = 1;
                }
                break;
        }

        char * msg_output = buffer[j];
        unsigned int original_j_for_nulling = j;
        forward(j, agt->buflength + 1);
        w_mutex_unlock(&mutex_lock);

        if (buff.warn){

            buff.warn = 0;
            mwarn(WARN_BUFFER, warn_level);
            snprintf(warn_str, OS_SIZE_2048, OS_WARN_BUFFER, warn_level);
            snprintf(warn_msg, OS_MAXSTR, "%c:%s:%s", LOCALFILE_MQ, "wazuh-agent", warn_str);
            send_msg(warn_msg, -1);
        }

        if (buff.full){

            buff.full = 0;
            mwarn(FULL_BUFFER);
            snprintf(full_msg, OS_MAXSTR, "%c:%s:%s", LOCALFILE_MQ, "wazuh-agent", OS_FULL_BUFFER);
            send_msg(full_msg, -1);
        }

        if (buff.flood){

            buff.flood = 0;
            mwarn(FLOODED_BUFFER);
            snprintf(flood_msg, OS_MAXSTR, "%c:%s:%s", LOCALFILE_MQ, "wazuh-agent", OS_FLOOD_BUFFER);
            send_msg(flood_msg, -1);
        }

        if (buff.normal){

            buff.normal = 0;
            minfo(NORMAL_BUFFER, normal_level);
            snprintf(normal_msg, OS_MAXSTR, "%c:%s:%s", LOCALFILE_MQ, "wazuh-agent", OS_NORMAL_BUFFER);
            send_msg(normal_msg, -1);
        }

        os_wait();
        send_msg(msg_output, -1);
        free(msg_output);
        buffer[original_j_for_nulling] = NULL; // Set that slot to NULL

        gettime(&ts1);
        time_sub(&ts1, &ts0);

        if (ts1.tv_sec >= 0) {
            delay(&ts1);
        }

        if (!agt->buffer) {
            minfo("Dispatch buffer thread received stop signal. Exiting.");
            break;
        }
    }
}

void delay(struct timespec * ts_loop) {
    long interval_ns = 1000000000 / agt->events_persec;
    struct timespec ts_timeout = { interval_ns / 1000000000, interval_ns % 1000000000 };
    time_sub(&ts_timeout, ts_loop);

    if (ts_timeout.tv_sec >= 0) {
        nanosleep(&ts_timeout, NULL);
    }
}

int w_agentd_get_buffer_lenght() {

    int retval = -1;

    if (agt->buffer > 0) {
        w_mutex_lock(&mutex_lock);
        retval = (i - j) % (agt->buflength + 1);
        w_mutex_unlock(&mutex_lock);

        retval = (retval < 0) ? (retval + agt->buflength + 1) : retval;
    }

    return retval;
}

void w_agentd_free_buffer(unsigned int current_capacity) {
    w_mutex_lock(&mutex_lock);

    // Ensure the buffer is actually allocated before trying to free.
    if ( buffer == NULL || current_capacity == 0) {
        minfo("Buffer is already unallocated or invalid. Skipping free operation.");
        w_mutex_unlock(&mutex_lock);
        return;
    }

    mdebug2("Freeing agent message buffer (capacity: %u)...", current_capacity);
    for (unsigned int k = 0; k < current_capacity; k++) {
        if (buffer[k] != NULL) {
            mdebug2("DEBUG: Attempting to free message at buffer[%u], address: %p", k, (void*)buffer[k]);
            free(buffer[k]);
            buffer[k] = NULL;
        }
    }

    mwarn("Freeing the client-buffer.");
    free(buffer);
    buffer = NULL;

    agt->buflength = 0;     // Reset capacity to 0
    i = 0;
    j = 0;

    w_mutex_unlock(&mutex_lock);
    minfo("Agent message buffer freed successfully.");
}

int resize_internal_buffer(unsigned int current_capacity, unsigned int desired_capacity) {
    unsigned int agent_msg_count = w_agentd_get_buffer_lenght();

    if (desired_capacity <= 0) {
        merror("Invalid new buffer capacity requested: %u.", desired_capacity);
        return -1;
    }

    if (desired_capacity == current_capacity) {
        return 0; // No change needed
    }

    // Attempt to reallocate the buffer
    w_mutex_lock(&mutex_lock);
    if (desired_capacity > current_capacity) {
        char **new_buffer_ptr = (char **)realloc(buffer, desired_capacity * sizeof(char *));
        if (new_buffer_ptr == NULL) {
            merror("Failed to reallocate client buffer to %u elements. Error: %s", desired_capacity, strerror(errno));
            w_mutex_unlock(&mutex_lock);
            return -1;
        }

        buffer = new_buffer_ptr; // Update the global pointer

        // If capacity increased, initialize new pointers to NULL to prevent dangling
        for (unsigned int k = current_capacity; k < desired_capacity; k++) {
            buffer[k] = NULL;
        }
    }else{
        mwarn("Shrinking client buffer from %u to %u (messages: %u).",
            current_capacity, desired_capacity, agent_msg_count);

        unsigned int new_actual_message_count = (agent_msg_count < desired_capacity) ? agent_msg_count : desired_capacity;
        unsigned int messages_to_discard = agent_msg_count - new_actual_message_count;

        // Free memory for messages that will be truncated (if any)
        if (messages_to_discard > 0) {
            mwarn("Truncating %u oldest messages due to buffer shrink.", messages_to_discard);
            unsigned int discard_idx = j; // Start from the current oldest message
            for (unsigned int k = 0; k < messages_to_discard; k++) {
                if (buffer[discard_idx] != NULL) {
                    mdebug2("Freeing buffer[%u] (ptr: %p)\n", discard_idx, (void*)buffer[discard_idx]);
                    free(buffer[discard_idx]);
                    buffer[discard_idx] = NULL;
                }
                discard_idx = (discard_idx + 1) % current_capacity;
            }
        }

        // Allocate a new temporary buffer of the desired smaller size
        char **temp_buffer = (char **)calloc(desired_capacity, sizeof(char *));
        if (temp_buffer == NULL) {
            merror("%s: Failed to allocate temporary buffer for shrinking to %u. Error: %s", __func__, desired_capacity, strerror(errno));
            w_mutex_unlock(&mutex_lock);
            return -1;
        }

        // Copy active elements from the old buffer to the new buffer
        // 'j' now points to the first message that should be kept (after discarding)
        unsigned int current_old_idx_for_copy = (j + messages_to_discard) % current_capacity; // Start from the new oldest message
        for (unsigned int k = 0; k < new_actual_message_count; k++) {
            temp_buffer[k] = buffer[current_old_idx_for_copy];
            buffer[current_old_idx_for_copy] = NULL;
            current_old_idx_for_copy = (current_old_idx_for_copy + 1) % current_capacity;
            mdebug2("Copying messages %i to the new buffer.\n", k);
        }
        minfo("Successfully copied %u messages to the new buffer.", new_actual_message_count);

        // Free the old buffer and update global pointer
        free(buffer);
        buffer = temp_buffer;

        // Update global buffer state variables for the new smaller buffer
        agent_msg_count = new_actual_message_count;
        w_agentd_state_update(RESET_MSG_COUNT_ON_SHRINK, &agent_msg_count);

        // Reset head and tail indices for the new, linear buffer
        j = 0; // Tail is now at the start
        i = agent_msg_count; // Head is after the last copied message
    }
    w_mutex_unlock(&mutex_lock);

    minfo("Client buffer resized from %u to %u elements.", current_capacity, desired_capacity);
    return 0;
}
