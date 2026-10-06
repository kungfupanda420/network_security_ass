#ifndef SCAN_DETECTOR_H
#define SCAN_DETECTOR_H

#include <stdint.h>

void analyze_packet_for_scan(uint32_t src_ip, uint16_t dest_port, const char* scan_type);

#endif