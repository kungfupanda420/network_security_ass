#ifndef RESPONSE_ENGINE_H
#define RESPONSE_ENGINE_H

#include <stdint.h>

typedef enum {
    RESPONSE_LOG = 1,
    RESPONSE_REDIRECT = 2,
    RESPONSE_BLOCK = 3
} ResponseAction;

// Added dest_port to pass the targeted port
void trigger_response(uint32_t ip_addr, uint16_t dest_port, ResponseAction action);

#endif