#include "ip_tracker.h"
#include <stdio.h>
#include <string.h>

static ip_record ip_table[MAX_TRACKED_IPS];
static int tracked_count = 0;

void init_tracker() {
    memset(ip_table, 0, sizeof(ip_table));
    tracked_count = 0;
}

ip_record* get_or_create_ip_record(uint32_t ip_addr) {
    for (int i = 0; i < tracked_count; i++) {
        if (ip_table[i].ip_addr == ip_addr) {
            return &ip_table[i];
        }
    }

    if (tracked_count < MAX_TRACKED_IPS) {
        ip_record *rec = &ip_table[tracked_count++];
        memset(rec, 0, sizeof(ip_record));
        rec->ip_addr = ip_addr;
        rec->first_packet_time = time(NULL);
        return rec;
    }

    return NULL; // Table full
}

int add_port_to_record(ip_record *rec, uint16_t port) {
    for (int i = 0; i < rec->unique_ports_count; i++) {
        if (rec->ports[i] == port) {
            return 0; // Port already recorded in this window
        }
    }

    if (rec->unique_ports_count < MAX_PORTS_PER_IP) {
        rec->ports[rec->unique_ports_count++] = port;
        return 1; // New unique port recorded
    }

    return 0;
}