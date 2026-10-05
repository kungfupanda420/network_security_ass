#include "packet_capture.h"

int create_raw_socket() {
    int sock_raw;

    sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    
    if (sock_raw < 0) {
        perror("Socket Error. Are you running as root?");
        exit(1);
    }
    
    return sock_raw;
}