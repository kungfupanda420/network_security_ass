#ifndef LOGGER_H
#define LOGGER_H

#include <stdint.h>

// Initialize the logging system
void logger_init();

// Log an event based on risk level and action taken
void log_attack_event(uint32_t ip_addr, const char *scan_type, int risk_tier, const char *action_taken);

#endif