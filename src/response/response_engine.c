#include "response_engine.h"
#include "iptables.h"
#include <stdio.h>

void trigger_response(uint32_t ip_addr, ResponseAction action) {
    switch(action) {
        case RESPONSE_LOG:
            printf("[RESPONSE] Applying LOW risk action: System Log.\n");
            iptables_log_ip(ip_addr);
            break;
            
        case RESPONSE_REDIRECT:
            printf("[RESPONSE] Applying MEDIUM risk action: Honeypot Redirect.\n");
            iptables_redirect_ip(ip_addr, HONEYPOT_PORT);
            break;
            
        case RESPONSE_BLOCK:
            printf("[RESPONSE] Applying HIGH risk action: Complete Block.\n");
            iptables_block_ip(ip_addr);
            break;
            
        default:
            printf("[RESPONSE] Unknown action requested.\n");
            break;
    }
}