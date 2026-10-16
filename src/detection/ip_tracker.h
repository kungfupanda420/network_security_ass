#ifndef IP_TRACKER_H
#define IP_TRACKER_H

#include <stdint.h>
#include <time.h>

#define MAX_TRACKED_IPS 1000
#define MAX_PORTS_PER_IP 100
#define SCAN_TIME_WINDOW 15  // Window set to 15 seconds

typedef struct {
    uint32_t ip_addr;
    time_t first_packet_time;
    uint16_t ports[MAX_PORTS_PER_IP]; // Array named 'ports' to match ip_tracker.c
    int unique_ports_count;
    int alert_triggered; // 0=None, 1=Low, 2=Medium, 3=High
} ip_record;

void init_tracker();
ip_record* get_or_create_ip_record(uint32_t ip_addr);
int add_port_to_record(ip_record *rec, uint16_t port);

#endif