#include "honeypot_common.h"

void* start_fake_ftp(void *arg) {
    (void)arg;
    int server_fd = create_listening_socket(HONEYPOT_FTP_PORT);
    int client_socket;
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];

    printf("[HONEYPOT] Fake FTP Service listening on port %d\n", HONEYPOT_FTP_PORT);

    while (1) {
        client_socket = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);
        if (client_socket < 0) continue;

        char *ip = inet_ntoa(client_addr.sin_addr);
        printf("\n[HONEYPOT-FTP] Connection received from %s\n", ip);

        // 1. Send FTP welcome banner
        const char *banner = "220 (vsFTPd 3.0.3)\r\n";
        send(client_socket, banner, strlen(banner), 0);

        // 2. Wait for USER command
        memset(buffer, 0, BUFFER_SIZE);
        recv(client_socket, buffer, BUFFER_SIZE, 0);
        buffer[strcspn(buffer, "\r\n")] = 0;
        printf("[HONEYPOT-FTP] %s sent: %s\n", ip, buffer);

        // 3. Ask for password
        const char *ask_pass = "331 Please specify the password.\r\n";
        send(client_socket, ask_pass, strlen(ask_pass), 0);

        // 4. Wait for PASS command
        memset(buffer, 0, BUFFER_SIZE);
        recv(client_socket, buffer, BUFFER_SIZE, 0);
        buffer[strcspn(buffer, "\r\n")] = 0;
        printf("[HONEYPOT-FTP] %s sent: %s\n", ip, buffer);

        // 5. Reject login and close
        const char *reject = "530 Login incorrect.\r\n";
        send(client_socket, reject, strlen(reject), 0);
        
        close(client_socket);
    }
    return NULL;
}