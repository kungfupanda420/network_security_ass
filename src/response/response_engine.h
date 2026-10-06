#ifndef RESPONSE_ENGINE_H
#define RESPONSE_ENGINE_H

#include <stdint.h>

#define HONEYPOT_PORT 2222 // Default port for your fake service

// Define action tiers matching your Module 3 requirements
typedef enum {
    RESPONSE_LOG = 1,
    RESPONSE_REDIRECT = 2,
    RESPONSE_BLOCK = 3
} ResponseAction;

void trigger_response(uint32_t ip_addr, ResponseAction action);

#endif