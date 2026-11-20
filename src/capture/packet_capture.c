#include "packet_capture.h"
#include "../detection/classifier.h"
#include "../detection/scan_detector.h"
#include "../honeypot/honeypot_common.h"

static uint32_t g_host_ip = 0;

static void load_host_ip(void) {
    const char *env_ip = getenv("HOST_IP");
    if (env_ip && strlen(env_ip) > 0) {
        struct in_addr addr;
        if (inet_pton(AF_INET, env_ip, &addr) == 1) {
            g_host_ip = addr.s_addr;
        }
    }
}

static int is_private_lan_ip(uint32_t ip_net_order) {
    uint32_t ip = ntohl(ip_net_order);
    if ((ip & 0xFF000000U) == 0x0A000000U) return 1; // 10.0.0.0/8
    if ((ip & 0xFFF00000U) == 0xAC100000U) return 1; // 172.16.0.0/12
    if ((ip & 0xFFFF0000U) == 0xC0A80000U) return 1; // 192.168.0.0/16
    return 0;
}

static int is_ignored_port(uint16_t port) {
    return (port == 5000 ||                 // Flask dashboard
            port == HONEYPOT_SSH_PORT ||    // 2222
            port == HONEYPOT_FTP_PORT ||    // 2121
            port == HONEYPOT_HTTP_PORT ||   // 8080
            port == 53 ||                   // DNS
            port == 123 ||                  // NTP
            port == 5353 ||                 // mDNS
            port == 1900);                  // SSDP
}

void process_packet(unsigned char *buffer, int size) {
    if (size < (int)sizeof(struct iphdr)) return;

    struct iphdr *iph = (struct iphdr *)buffer;
    int iphdrlen = iph->ihl * 4;
    if (iph->protocol != IPPROTO_TCP || size < iphdrlen + (int)sizeof(struct tcphdr)) {
        return;
    }

    // 1. Local LAN source IPs only (drops NTP servers & all public internet traffic)
    if (!is_private_lan_ip(iph->saddr)) return;

    // 2. Ignore outbound traffic from this host and packets not aimed at this host
    if (g_host_ip != 0) {
        if (iph->saddr == g_host_ip) return;
        if (iph->daddr != g_host_ip) return;
    }

    struct tcphdr *tcph = (struct tcphdr *)(buffer + iphdrlen);
    uint16_t src_port = ntohs(tcph->source);
    uint16_t dest_port = ntohs(tcph->dest);

    // 3. Ignore dashboard, honeypot, and noisy background service ports
    if (is_ignored_port(src_port) || is_ignored_port(dest_port)) {
        return;
    }

    const char *scan_type = classify_packet(tcph);

    // 4. Ignore pure ACKs hitting ephemeral local client ports (normal LAN replies)
    if (strcmp(scan_type, "ACK") == 0 && dest_port >= 32768) {
        return;
    }

    // 5. Fixed uppercase "NORMAL" check + thread-safe inet_ntop
    if (strcmp(scan_type, "NORMAL") != 0) {
        char src_str[INET_ADDRSTRLEN];
        char dst_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &iph->saddr, src_str, sizeof(src_str));
        inet_ntop(AF_INET, &iph->daddr, dst_str, sizeof(dst_str));

        printf("LAN %s:%u -> %s:%u [Type: %s]\n",
               src_str, src_port, dst_str, dest_port, scan_type);

        analyze_packet_for_scan(iph->saddr, dest_port, scan_type);
    }
}

void start_packet_capture(int sock_raw) {
    load_host_ip();

    unsigned char *buffer = (unsigned char *)malloc(CAPTURE_BUFFER_SIZE);
    if (!buffer) {
        perror("Failed to allocate buffer");
        exit(1);
    }

    printf("Starting packet capture (Local LAN incoming TCP only)...\n");

    while (1) {
        struct sockaddr saddr;
        socklen_t saddr_size = sizeof(saddr);

        ssize_t data_size = recvfrom(sock_raw, buffer, CAPTURE_BUFFER_SIZE, 0, &saddr, &saddr_size);
        if (data_size < 0) {
            perror("Recvfrom error");
            break;
        }

        process_packet(buffer, (int)data_size);
    }
    free(buffer);
}