#include "iptables.h"
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

// Helper function to convert uint32_t IP to string safely
static void get_ip_str(uint32_t ip_addr, char *ip_str) {
    struct in_addr ip;
    ip.s_addr = ip_addr;
    sprintf(ip_str, "%s", inet_ntoa(ip));
}

void iptables_log_ip(uint32_t ip_addr) {
    char ip_str[INET_ADDRSTRLEN];
    get_ip_str(ip_addr, ip_str);
    
    char cmd[256];
    // Add a logging rule for this specific IP with a custom prefix
    snprintf(cmd, sizeof(cmd), 
             "iptables -A INPUT -s %s -j LOG --log-prefix \"[IDS_LOW_RISK] \"", 
             ip_str);
    
    printf("[EXEC] %s\n", cmd);
    system(cmd);
}

void iptables_redirect_ip(uint32_t ip_addr, uint16_t target_port, uint16_t honeypot_port) {
    char ip_str[INET_ADDRSTRLEN];
    get_ip_str(ip_addr, ip_str);
    
    char cmd[256];
    // NAT PREROUTING: Redirect specific target port to our honeypot port
    snprintf(cmd, sizeof(cmd), 
             "iptables -t nat -A PREROUTING -s %s -p tcp --dport %u -j REDIRECT --to-port %u", 
             ip_str, target_port, honeypot_port);
             
    printf("[EXEC] %s\n", cmd);
    system(cmd);
}
void iptables_block_ip(uint32_t ip_addr) {
    char ip_str[INET_ADDRSTRLEN];
    get_ip_str(ip_addr, ip_str);
    
    char cmd[256];
    // Drop all packets from this IP
    snprintf(cmd, sizeof(cmd), 
             "iptables -A INPUT -s %s -j DROP", 
             ip_str);
             
    printf("[EXEC] %s\n", cmd);
    system(cmd);
}