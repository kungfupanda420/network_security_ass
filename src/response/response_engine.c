#include "response_engine.h"
#include "iptables.h"
#include <stdio.h>

void trigger_response(uint32_t ip_addr, uint16_t dest_port, ResponseAction action) {
    uint16_t honeypot_port = 8080; // Default fallback (Fake HTTP)

    switch(action) {
        case RESPONSE_LOG:
            printf("[RESPONSE] Applying LOW risk action: System Log.\n");
            iptables_log_ip(ip_addr);
            break;
            
        case RESPONSE_REDIRECT:
            // Route to the correct fake service based on the targeted port
            if (dest_port == 22) {
                honeypot_port = 2222; // SSH
                printf("[RESPONSE] MEDIUM risk: Redirecting port 22 to Fake SSH (2222).\n");
            } else if (dest_port == 21) {
                honeypot_port = 2121; // FTP
                printf("[RESPONSE] MEDIUM risk: Redirecting port 21 to Fake FTP (2121).\n");
            } else {
                printf("[RESPONSE] MEDIUM risk: Redirecting port %d to Fake HTTP (8080).\n", dest_port);
            }
            
            iptables_redirect_ip(ip_addr, dest_port, honeypot_port);
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