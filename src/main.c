#include "capture/packet_capture.h"
#include "detection/ip_tracker.h"
#include "logging/logger.h"
#include "honeypot/honeypot_common.h"
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main()
{
    // Raw sockets require root privileges in Linux
    if (geteuid() != 0)
    {
        fprintf(stderr, "Error: You must run this program as root (sudo).\n");
        exit(1);
    }

    // Initialize the IP tracking system
    init_tracker();

    // Initialize logging and database
    logger_init();

    // (Inside main.c, right before start_packet_capture)

    pthread_t ssh_thread, ftp_thread, http_thread;

    // Launch honeypots in background threads
    pthread_create(&ssh_thread, NULL, start_fake_ssh, NULL);
    pthread_create(&ftp_thread, NULL, start_fake_ftp, NULL);
    pthread_create(&http_thread, NULL, start_fake_http, NULL);

    // 1. Initialize the raw socket
    int sock_raw = create_raw_socket();
    // 2. Enter the infinite packet capture loop
    start_packet_capture(sock_raw);

    // Clean up (unreachable in current infinite loop)
    close(sock_raw);
    return 0;
}