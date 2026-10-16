#include "packet_capture.h"
#include "../detection/classifier.h"
#include "../detection/scan_detector.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

// Renamed to avoid conflict with the honeypot BUFFER_SIZE
#define CAPTURE_BUFFER_SIZE 65536 

void process_packet(unsigned char *buffer, int size) {
    (void)size; // Tells the compiler we intentionally aren't using this variable yet
    
    struct iphdr *iph = (struct iphdr *)buffer;
    int iphdrlen = iph->ihl * 4;

    if (iph->protocol == 6) { // TCP Protocol
        struct tcphdr *tcph = (struct tcphdr *)(buffer + iphdrlen);
        
        // ---> FILTER: Ignore traffic to/from the Flask Dashboard (Port 5000) <---
        if (ntohs(tcph->source) == 5000 || ntohs(tcph->dest) == 5000) {
            return;
        }

        const char* scan_type = classify_packet(tcph);
        
        // Only log and process if it is classified as a suspicious packet
        if (strcmp(scan_type, "Normal") != 0) {
            struct in_addr src_ip, dest_ip;
            src_ip.s_addr = iph->saddr;
            dest_ip.s_addr = iph->daddr;
            
            uint16_t dest_port = ntohs(tcph->dest);
            
            printf("IP %s:%u -> %s:%u [Type: %s]\n", 
                   inet_ntoa(src_ip), ntohs(tcph->source), 
                   inet_ntoa(dest_ip), dest_port, scan_type);

            // Pass the source IP, destination port, and scan type to the detection engine
            analyze_packet_for_scan(iph->saddr, dest_port, scan_type);
        }
    }
}

void start_packet_capture(int sock_raw) {
    unsigned char *buffer = (unsigned char *)malloc(CAPTURE_BUFFER_SIZE);
    if (!buffer) {
        perror("Failed to allocate buffer");
        exit(1);
    }

    printf("Starting packet capture. Listening for incoming TCP packets...\n");

    while (1) {
        struct sockaddr saddr;
        int saddr_size = sizeof(saddr);
        
        int data_size = recvfrom(sock_raw, buffer, CAPTURE_BUFFER_SIZE, 0, &saddr, (socklen_t*)&saddr_size);
        if (data_size < 0) {
            perror("Recvfrom error");
            return;
        }
        
        process_packet(buffer, data_size);
    }
    free(buffer);
}