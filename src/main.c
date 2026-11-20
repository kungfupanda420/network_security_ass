#include "capture/packet_capture.h"
#include "detection/ip_tracker.h"
#include "logging/logger.h"
#include "honeypot/honeypot_common.h"
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    if (geteuid() != 0)
    {
        fprintf(stderr, "Error: You must run this program as root (sudo).\n");
        exit(1);
    }

    // Prevent closed/reset honeypot sockets from killing the entire engine
    signal(SIGPIPE, SIG_IGN);

    init_tracker();
    logger_init();

    pthread_t ssh_thread, ftp_thread, http_thread;

    pthread_create(&ssh_thread, NULL, start_fake_ssh, NULL);
    pthread_create(&ftp_thread, NULL, start_fake_ftp, NULL);
    pthread_create(&http_thread, NULL, start_fake_http, NULL);

    int sock_raw = create_raw_socket();
    start_packet_capture(sock_raw);

    close(sock_raw);
    return 0;
}