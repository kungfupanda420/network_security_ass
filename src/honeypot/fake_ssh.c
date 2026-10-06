#include "honeypot_common.h"

int create_listening_socket(int port) {
    int server_fd;
    struct sockaddr_in address;
    int opt = 1;

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }
    
    // Prevent "Address already in use" errors during rapid testing
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }
    
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }
    
    return server_fd;
}

void* start_fake_ssh(void *arg) {
    (void)arg; // Unused
    int server_fd = create_listening_socket(HONEYPOT_SSH_PORT);
    int client_socket;
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];

    printf("[HONEYPOT] Fake SSH Service listening on port %d\n", HONEYPOT_SSH_PORT);

    while (1) {
        client_socket = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);
        if (client_socket < 0) continue;

        char *ip = inet_ntoa(client_addr.sin_addr);
        printf("\n[HONEYPOT-SSH] Connection received from %s\n", ip);

        // Send a realistic OpenSSH banner
        const char *banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n";
        send(client_socket, banner, strlen(banner), 0);

        // Read the attacker's client identification string
        memset(buffer, 0, BUFFER_SIZE);
        recv(client_socket, buffer, BUFFER_SIZE, 0);

        // Remove trailing newlines for clean printing
        buffer[strcspn(buffer, "\r\n")] = 0; 
        printf("[HONEYPOT-SSH] Attacker %s used client: %s\n", ip, buffer);

        // Close connection before cryptographic handshake is required
        close(client_socket);
    }
    return NULL;
}