#include "honeypot_common.h"
#include "../logging/db_sqlite.h"

void* start_fake_ftp(void *arg) {
    (void)arg;
    int server_fd = create_listening_socket(HONEYPOT_FTP_PORT);
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];

    printf("[HONEYPOT] Fake FTP Service listening on port %d\n", HONEYPOT_FTP_PORT);

    while (1) {
        int client_socket = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);
        if (client_socket < 0) continue;

        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, ip, sizeof(ip));
        printf("[HONEYPOT-FTP] Connection received from %s\n", ip);
        db_insert_honeypot_log("FTP", ip, "CONNECT", "FTP session opened");

        const char *banner = "220 (vsFTPd 3.0.3)\r\n";
        send(client_socket, banner, strlen(banner), 0);

        memset(buffer, 0, BUFFER_SIZE);
        if (recv(client_socket, buffer, BUFFER_SIZE - 1, 0) > 0) {
            buffer[strcspn(buffer, "\r\n")] = 0;
            printf("[HONEYPOT-FTP] %s sent: %s\n", ip, buffer);
            db_insert_honeypot_log("FTP", ip, "USER", buffer);
        }

        const char *ask_pass = "331 Please specify the password.\r\n";
        send(client_socket, ask_pass, strlen(ask_pass), 0);

        memset(buffer, 0, BUFFER_SIZE);
        if (recv(client_socket, buffer, BUFFER_SIZE - 1, 0) > 0) {
            buffer[strcspn(buffer, "\r\n")] = 0;
            printf("[HONEYPOT-FTP] %s sent: %s\n", ip, buffer);
            db_insert_honeypot_log("FTP", ip, "PASS", buffer);
            db_insert_event(ip, 21, "FTP_LOGIN", "MEDIUM", "FTP_HONEYPOT_TRAP");
        }

        const char *reject = "530 Login incorrect.\r\n";
        send(client_socket, reject, strlen(reject), 0);

        close(client_socket);
    }
    return NULL;
}