#include "classifier.h"

const char* classify_packet(const struct tcphdr *tcph) {
    // NULL scan: No flags set
    if (!tcph->syn && !tcph->fin && !tcph->rst && !tcph->psh && !tcph->ack && !tcph->urg) {
        return "NULL";
    }
    // XMAS scan: FIN, PSH, and URG set
    else if (tcph->fin && tcph->psh && tcph->urg) {
        return "XMAS";
    }
    // SYN scan: SYN set, ACK not set
    else if (tcph->syn && !tcph->ack) {
        return "SYN";
    }
    // FIN scan: FIN set, ACK not set, and not XMAS
    else if (tcph->fin && !tcph->ack && !tcph->urg && !tcph->psh) {
        return "FIN";
    }
    // ACK scan: ACK set (used by Nmap to map firewall rules)
    else if (tcph->ack && !tcph->syn && !tcph->fin && !tcph->rst) {
        return "ACK";
    }
    
    return "NORMAL"; 
}