#include "ip_tracker.h"
#include <string.h>

// Simple fixed array for tracking to keep memory management safe and fast
static ip_record tracker[MAX_TRACKED_IPS];
static int active_ips = 0;

void init_tracker() {
    memset(tracker, 0, sizeof(tracker));
    active_ips = 0;
}

ip_record* get_or_create_ip_record(uint32_t ip_addr) {
    // 1. Check if IP already exists
    for (int i = 0; i < active_ips; i++) {
        if (tracker[i].ip_addr == ip_addr) {
            return &tracker[i];
        }
    }

    // 2. If not found, create a new record (if we have space)
    if (active_ips < MAX_TRACKED_IPS) {
        tracker[active_ips].ip_addr = ip_addr;
        tracker[active_ips].unique_ports_count = 0;
        tracker[active_ips].first_packet_time = time(NULL);
        tracker[active_ips].alert_triggered = 0;
        active_ips++;
        return &tracker[active_ips - 1];
    }

    // Tracker is full (in a real scenario, you would evict the oldest entry)
    return NULL; 
}

// Returns 1 if a new port was added, 0 if it was a duplicate
int add_port_to_record(ip_record *record, uint16_t port) {
    // Check for duplicates
    for (int i = 0; i < record->unique_ports_count; i++) {
        if (record->ports[i] == port) {
            return 0; // Port already tracked
        }
    }

    // Add new port if under limit
    if (record->unique_ports_count < MAX_PORTS_PER_IP) {
        record->ports[record->unique_ports_count] = port;
        record->unique_ports_count++;
        return 1;
    }
    return 0;
}