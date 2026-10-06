#ifndef LOGGER_H
#define LOGGER_H

#include <stdint.h>

void logger_init();

// Added dest_port
void log_attack_event(uint32_t ip_addr, uint16_t dest_port, const char *scan_type, int risk_tier, const char *action_taken);

#endif