#include "honeypot_common.h"
#include "../logging/db_sqlite.h"
#include <sys/time.h>

#define HTTP_BUF_SIZE 4096

void* start_fake_http(void *arg) {
    (void)arg;
    int server_fd = create_listening_socket(HONEYPOT_HTTP_PORT);
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    char buffer[HTTP_BUF_SIZE];

    printf("[HONEYPOT] Fake HTTP Service listening on port %d\n", HONEYPOT_HTTP_PORT);

    const char *login_page =
        "HTTP/1.1 200 OK\r\n"
        "Server: Apache/2.4.52 (Ubuntu)\r\n"
        "Content-Type: text/html\r\n"
        "Connection: close\r\n\r\n"
        "<html><head><title>Router Admin Portal</title></head><body>"
        "<h2>Gateway Admin Portal</h2>"
        "<form method='POST' action='/login'>"
        "Username: <input type='text' name='user'><br><br>"
        "Password: <input type='password' name='pass'><br><br>"
        "<input type='submit' value='Sign In'></form></body></html>\n";

    const char *dashboard_page =
        "HTTP/1.1 200 OK\r\n"
        "Server: Apache/2.4.52 (Ubuntu)\r\n"
        "Content-Type: text/html\r\n"
        "Connection: close\r\n\r\n"
        "<html><head><title>Admin Dashboard</title></head><body>"
        "<h2>Gateway Diagnostics (Authenticated)</h2>"
        "<p>Status: Online | Firmware: v4.2.1-rc3</p>"
        "<form method='POST' action='/ping'>"
        "Ping Host: <input type='text' name='host' value='8.8.8.8'> "
        "<input type='submit' value='Run'></form>"
        "<pre>PING 8.8.8.8: 64 bytes icmp_seq=1 ttl=118 time=12.4 ms</pre>"
        "</body></html>\n";

    while (1) {
        int client_socket = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);
        if (client_socket < 0) continue;

        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, ip, sizeof(ip));

        memset(buffer, 0, sizeof(buffer));
        ssize_t total = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
        if (total <= 0) {
            close(client_socket);
            continue;
        }

        char *body = strstr(buffer, "\r\n\r\n");
        if (body) {
            body += 4;
            if (strncmp(buffer, "POST ", 5) == 0 && strlen(body) == 0 && total < (ssize_t)(sizeof(buffer) - 1)) {
                ssize_t more = recv(client_socket, buffer + total, sizeof(buffer) - 1 - total, 0);
                if (more > 0) buffer[total + more] = '\0';
            }
        }

        char req_line[256] = {0};
        char *line_end = strstr(buffer, "\r\n");
        if (line_end) {
            size_t len = (size_t)(line_end - buffer);
            if (len >= sizeof(req_line)) len = sizeof(req_line) - 1;
            memcpy(req_line, buffer, len);
        }

        printf("[HONEYPOT-HTTP] %s -> %s\n", ip, req_line);
        db_insert_honeypot_log("HTTP", ip, "REQUEST", req_line);

        if (body && strlen(body) > 0) {
            printf("[HONEYPOT-HTTP] %s POST DATA: %s\n", ip, body);
            db_insert_honeypot_log("HTTP", ip, "POST_PAYLOAD", body);
            db_insert_event(ip, 80, "HTTP_POST", "MEDIUM", "HTTP_HONEYPOT_TRAP");
        }

        if (strncmp(req_line, "POST /login", 11) == 0 ||
            strncmp(req_line, "POST /ping", 10) == 0 ||
            strncmp(req_line, "GET /dashboard", 14) == 0) {
            send(client_socket, dashboard_page, strlen(dashboard_page), 0);
        } else {
            send(client_socket, login_page, strlen(login_page), 0);
        }

        close(client_socket);
    }
    return NULL;
}