#include "capture/packet_capture.h"
#include "detection/ip_tracker.h"
int main() {
    init_tracker();
    // Raw sockets require root privileges in Linux
    if (geteuid() != 0) {
        fprintf(stderr, "Error: You must run this program as root (sudo).\n");
        exit(1);
    }

    // 1. Initialize the raw socket
    int sock_raw = create_raw_socket();

    // 2. Enter the infinite packet capture loop
    start_packet_capture(sock_raw);

    // Clean up (unreachable in current infinite loop, but good practice)
    close(sock_raw);
    return 0;
}