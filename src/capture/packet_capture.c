#include "packet_capture.h"
#include "../detection/scan_detector.h"
#include "detection/classifier.h"

void start_packet_capture(int sock_raw) {
    unsigned char *buffer = (unsigned char *)malloc(BUFFER_SIZE);
    if (!buffer) {
        perror("Memory allocation failed");
        exit(1);
    }

    struct sockaddr_in saddr;
    int saddr_len = sizeof(saddr);

    printf("Starting packet capture. Listening for incoming TCP packets...\n");

    while (1) {
        // Receive a packet
        int data_size = recvfrom(sock_raw, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&saddr, (socklen_t*)&saddr_len);
        
        if (data_size < 0) {
            perror("Recvfrom error");
            return;
        }
        
        process_packet(buffer, data_size);
    }
    
    free(buffer);
}

void process_packet(unsigned char *buffer, int size) {
    struct iphdr *iph = (struct iphdr *)buffer;
    unsigned short iphdrlen = iph->ihl * 4;
    struct tcphdr *tcph = (struct tcphdr *)(buffer + iphdrlen);
    
    // 1. Classify the packet using your new module
    const char* scan_type = classify_packet(tcph);

    // Skip normal traffic to avoid filling up the terminal and tracking array
    if (strcmp(scan_type, "NORMAL") == 0) {
        return;
    }

    struct sockaddr_in source, dest;
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    // 2. Print suspicious packets
    printf("IP %s:%u -> ", inet_ntoa(source.sin_addr), ntohs(tcph->source));
    printf("%s:%u [Type: %s]\n", inet_ntoa(dest.sin_addr), ntohs(tcph->dest), scan_type);

    // 3. Send to the detection engine
    analyze_packet_for_scan(iph->saddr, ntohs(tcph->dest), scan_type);
}