#include "scan_detector.h"
#include "ip_tracker.h"
#include "../response/response_engine.h"
#include "../logging/logger.h"
#include <stdio.h>
#include <arpa/inet.h>
#include <time.h>

void analyze_packet_for_scan(uint32_t src_ip, uint16_t dest_port, const char* scan_type) {
    ip_record *rec = get_or_create_ip_record(src_ip);
    if (!rec) return; // Tracker is full

    time_t now = time(NULL);

    // If time window has expired, reset the tracker for this IP
    if (now - rec->first_packet_time > SCAN_TIME_WINDOW) {
        rec->first_packet_time = now;
        rec->unique_ports_count = 0;
        rec->alert_triggered = 0;
    }

    // Add port and check against our tiered thresholds
    if (add_port_to_record(rec, dest_port)) {
        int ports_hit = rec->unique_ports_count;
        
        struct in_addr ip_struct;
        ip_struct.s_addr = src_ip;

        // Tier 1: LOW RISK (5 ports)
        if (ports_hit == 5 && rec->alert_triggered < 1) {
            printf("\n[!] RISK: LOW - Suspicious activity from %s\n", inet_ntoa(ip_struct));
            trigger_response(src_ip, RESPONSE_LOG);
            log_attack_event(src_ip, scan_type, 1, "IPTABLES_LOG");
            rec->alert_triggered = 1;
        } 
        // Tier 2: MEDIUM RISK (15 ports)
        else if (ports_hit == 15 && rec->alert_triggered < 2) {
            printf("\n[!!] RISK: MEDIUM - %s Scan Detected from %s\n", scan_type, inet_ntoa(ip_struct));
            trigger_response(src_ip, RESPONSE_REDIRECT);
            log_attack_event(src_ip, scan_type, 2, "REDIRECT_HONEYPOT");
            rec->alert_triggered = 2;
        } 
        // Tier 3: HIGH RISK (30+ ports)
        else if (ports_hit == 30 && rec->alert_triggered < 3) {
            printf("\n[!!!] RISK: HIGH - Aggressive Attack from %s. Blocking!\n", inet_ntoa(ip_struct));
            trigger_response(src_ip, RESPONSE_BLOCK);
            log_attack_event(src_ip, scan_type, 3, "FIREWALL_BLOCK");
            rec->alert_triggered = 3;
        }
    }
}