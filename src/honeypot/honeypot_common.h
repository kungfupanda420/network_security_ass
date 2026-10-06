#ifndef HONEYPOT_COMMON_H
#define HONEYPOT_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#define HONEYPOT_SSH_PORT 2222
#define HONEYPOT_FTP_PORT 2121
#define HONEYPOT_HTTP_PORT 8080
#define BUFFER_SIZE 1024

// Thread entry points for the fake services
void* start_fake_ssh(void *arg);
void* start_fake_ftp(void *arg);
void* start_fake_http(void *arg);

// Helper to create a listening TCP socket
int create_listening_socket(int port);

#endif