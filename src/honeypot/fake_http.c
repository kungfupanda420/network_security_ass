#include "honeypot_common.h"

void* start_fake_http(void *arg) {
    (void)arg;
    int server_fd = create_listening_socket(HONEYPOT_HTTP_PORT);
    int client_socket;
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];

    printf("[HONEYPOT] Fake HTTP Service listening on port %d\n", HONEYPOT_HTTP_PORT);

    // A fake HTML response looking like a router admin page
    const char *http_response = 
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "Connection: close\r\n\r\n"
        "<html><body><h1>Admin Portal</h1>"
        "<form method='POST' action='/login'>"
        "User: <input type='text' name='user'><br>"
        "Pass: <input type='password' name='pass'><br>"
        "<input type='submit' value='Login'></form></body></html>\n";

    while (1) {
        client_socket = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);
        if (client_socket < 0) continue;

        char *ip = inet_ntoa(client_addr.sin_addr);
        
        memset(buffer, 0, BUFFER_SIZE);
        recv(client_socket, buffer, BUFFER_SIZE, 0);

        // Extract just the first line of the HTTP request (e.g., "GET /admin HTTP/1.1")
        char *first_line = strtok(buffer, "\r\n");
        if (first_line != NULL) {
            printf("\n[HONEYPOT-HTTP] %s requested: %s\n", ip, first_line);
        }

        send(client_socket, http_response, strlen(http_response), 0);
        close(client_socket);
    }
    return NULL;
}