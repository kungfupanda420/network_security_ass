#include "packet_capture.h"

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
    // The buffer contains the IP header at the very beginning
    struct iphdr *iph = (struct iphdr *)buffer;
    
    // Calculate the length of the IP header (ihl is in 32-bit words, so multiply by 4)
    unsigned short iphdrlen = iph->ihl * 4;
    
    // The TCP header starts immediately after the IP header
    struct tcphdr *tcph = (struct tcphdr *)(buffer + iphdrlen);
    
    struct sockaddr_in source, dest;
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
    
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    // Print packet details
    printf("IP %s:%u -> ", inet_ntoa(source.sin_addr), ntohs(tcph->source));
    printf("%s:%u ", inet_ntoa(dest.sin_addr), ntohs(tcph->dest));
    
    // Print TCP Flags to identify scan types (SYN, FIN, NULL, XMAS)
    printf("[Flags:");
    if (tcph->syn) printf(" SYN");
    if (tcph->fin) printf(" FIN");
    if (tcph->rst) printf(" RST");
    if (tcph->psh) printf(" PSH");
    if (tcph->ack) printf(" ACK");
    if (tcph->urg) printf(" URG");
    
    // Detect NULL scan (no flags set)
    if (!tcph->syn && !tcph->fin && !tcph->rst && !tcph->psh && !tcph->ack && !tcph->urg) {
        printf(" NONE (NULL)");
    }
    printf(" ]\n");
}