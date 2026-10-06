#ifndef IPTABLES_H
#define IPTABLES_H

#include <stdint.h>

void iptables_log_ip(uint32_t ip_addr);
// Added target_port and honeypot_port
void iptables_redirect_ip(uint32_t ip_addr, uint16_t target_port, uint16_t honeypot_port);
void iptables_block_ip(uint32_t ip_addr);

#endif