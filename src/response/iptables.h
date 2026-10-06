#ifndef IPTABLES_H
#define IPTABLES_H

#include <stdint.h>

// Functions to interact directly with the Linux firewall
void iptables_log_ip(uint32_t ip_addr);
void iptables_redirect_ip(uint32_t ip_addr, uint16_t honeypot_port);
void iptables_block_ip(uint32_t ip_addr);

#endif