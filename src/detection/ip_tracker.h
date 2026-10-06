#ifndef IP_TRACKER_H
#define IP_TRACKER_H

#include <stdint.h>
#include <time.h>

#define MAX_TRACKED_IPS 1000
#define MAX_PORTS_PER_IP 50
#define SCAN_TIME_WINDOW 5       // Time window in seconds
#define PORT_SCAN_THRESHOLD 15   // Unique ports hit to trigger alert

// Structure to track an attacker's behavior
typedef struct {
    uint32_t ip_addr;                     // Source IP
    uint16_t ports[MAX_PORTS_PER_IP];     // Array of unique ports accessed
    int unique_ports_count;               // How many unique ports
    time_t first_packet_time;             // Timestamp of the first packet
    int alert_triggered;                  // Flag to prevent spamming the console
} ip_record;

// Function prototypes
void init_tracker();
ip_record* get_or_create_ip_record(uint32_t ip_addr);
int add_port_to_record(ip_record *record, uint16_t port);

#endif