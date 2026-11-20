#include "response_engine.h"
#include "iptables.h"
#include "../honeypot/honeypot_common.h"
#include <stdio.h>

void trigger_response(uint32_t ip_addr, uint16_t dest_port, ResponseAction action) {
    switch (action) {
        case RESPONSE_LOG:
            printf("[RESPONSE] Applying LOW risk action: System Log.\n");
            iptables_log_ip(ip_addr);
            break;

        case RESPONSE_REDIRECT:
            printf("[RESPONSE] MEDIUM risk: Trapping attacker into Fake HTTP (80->%d), SSH (22->%d), FTP (21->%d).\n",
                   HONEYPOT_HTTP_PORT, HONEYPOT_SSH_PORT, HONEYPOT_FTP_PORT);

            // Always trap standard HTTP, SSH, and FTP ports for this attacker
            iptables_redirect_ip(ip_addr, 80, HONEYPOT_HTTP_PORT);
            iptables_redirect_ip(ip_addr, 22, HONEYPOT_SSH_PORT);
            iptables_redirect_ip(ip_addr, 21, HONEYPOT_FTP_PORT);

            // If they hit another port (e.g., 8000/443), route it to Fake HTTP too
            if (dest_port != 80 && dest_port != 22 && dest_port != 21) {
                iptables_redirect_ip(ip_addr, dest_port, HONEYPOT_HTTP_PORT);
            }
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