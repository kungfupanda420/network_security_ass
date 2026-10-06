#ifndef PACKET_CAPTURE_H
#define PACKET_CAPTURE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 65536

int create_raw_socket();
void start_packet_capture(int sock_raw);
void process_packet(unsigned char *buffer, int size);

#endif