#include "honeypot_common.h"
#include "../logging/db_sqlite.h"
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <stdarg.h>
#include <time.h>
#include <ctype.h>

#define SSH_HOST_KEY_PATH "logs/honeypot_rsa_key"
#define SSH_KEYLOG_PATH   "logs/ssh_keystrokes.log"

static pthread_mutex_t ssh_log_mutex = PTHREAD_MUTEX_INITIALIZER;

int create_listening_socket(int port) {
    int server_fd;
    struct sockaddr_in address;
    int opt = 1;

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 10) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    return server_fd;
}

static void log_ssh_file(const char *ip, const char *fmt, ...) {
    pthread_mutex_lock(&ssh_log_mutex);
    FILE *fp = fopen(SSH_KEYLOG_PATH, "a");
    if (fp) {
        time_t now = time(NULL);
        struct tm tm_now;
        localtime_r(&now, &tm_now);
        char ts[32];
        strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm_now);

        fprintf(fp, "[%s] [%s] ", ts, ip);
        va_list args;
        va_start(args, fmt);
        vfprintf(fp, fmt, args);
        va_end(args);
        fflush(fp);
        fclose(fp);
    }
    pthread_mutex_unlock(&ssh_log_mutex);
}

static void log_raw_key(const char *ip, const char *user, unsigned char ch) {
    char key_str[16];
    if (ch == '\r' || ch == '\n') snprintf(key_str, sizeof(key_str), "[ENTER]");
    else if (ch == 0x7f || ch == 0x08) snprintf(key_str, sizeof(key_str), "[BACKSPACE]");
    else if (ch == 0x03) snprintf(key_str, sizeof(key_str), "[CTRL+C]");
    else if (ch == 0x04) snprintf(key_str, sizeof(key_str), "[CTRL+D]");
    else if (ch == '\t') snprintf(key_str, sizeof(key_str), "[TAB]");
    else if (ch == 0x1b) snprintf(key_str, sizeof(key_str), "[ESC]");
    else if (isprint(ch)) snprintf(key_str, sizeof(key_str), "%c", ch);
    else snprintf(key_str, sizeof(key_str), "[0x%02X]", ch);

    log_ssh_file(ip, "[KEY:%s] %s\n", user, key_str);
    db_insert_keystroke(ip, user, key_str);
}

static void send_fake_command_output(ssh_channel chan, const char *user, const char *cmd) {
    char reply[1024];

    if (strlen(cmd) == 0) {
        return;
    } else if (strcmp(cmd, "whoami") == 0) {
        snprintf(reply, sizeof(reply), "%s\r\n", user);
    } else if (strcmp(cmd, "id") == 0) {
        snprintf(reply, sizeof(reply), "uid=0(%s) gid=0(root) groups=0(root)\r\n", user);
    } else if (strcmp(cmd, "pwd") == 0) {
        snprintf(reply, sizeof(reply), "/root\r\n");
    } else if (strncmp(cmd, "ls", 2) == 0) {
        snprintf(reply, sizeof(reply), "backup.sql  config.ini  deploy.sh  passwords.txt\r\n");
    } else if (strncmp(cmd, "uname", 5) == 0) {
        snprintf(reply, sizeof(reply), "Linux ubuntu-prod 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\r\n");
    } else if (strstr(cmd, "cat passwords.txt") != NULL) {
        snprintf(reply, sizeof(reply), "admin:Adm1n@2026!\r\ndb_root:ProdDB#991\r\n");
    } else {
        snprintf(reply, sizeof(reply), "bash: %s: command not found\r\n", cmd);
    }

    ssh_channel_write(chan, reply, (uint32_t)strlen(reply));
}

static void* handle_ssh_client(void *arg) {
    ssh_session session = (ssh_session)arg;
    ssh_message message;
    ssh_channel chan = NULL;
    int authenticated = 0;
    int shell_requested = 0;
    char username[128] = "root";
    char ip[INET_ADDRSTRLEN] = "unknown";

    struct sockaddr_in peer;
    socklen_t peer_len = sizeof(peer);
    if (getpeername(ssh_get_fd(session), (struct sockaddr *)&peer, &peer_len) == 0) {
        inet_ntop(AF_INET, &peer.sin_addr, ip, sizeof(ip));
    }

    printf("[HONEYPOT-SSH] Connection received from %s\n", ip);
    db_insert_honeypot_log("SSH", ip, "CONNECT", "SSH session opened");

    if (ssh_handle_key_exchange(session) != SSH_OK) {
        ssh_disconnect(session);
        ssh_free(session);
        return NULL;
    }

    while (!authenticated && (message = ssh_message_get(session)) != NULL) {
        if (ssh_message_type(message) == SSH_REQUEST_AUTH) {
            if (ssh_message_subtype(message) == SSH_AUTH_METHOD_PASSWORD) {
                const char *u = ssh_message_auth_user(message);
                const char *p = ssh_message_auth_password(message);
                snprintf(username, sizeof(username), "%s", u ? u : "unknown");

                char creds[320];
                snprintf(creds, sizeof(creds), "user=%s pass=%s", username, p ? p : "");

                printf("[HONEYPOT-SSH] LOGIN ACCEPTED from %s (%s)\n", ip, creds);
                log_ssh_file(ip, "[AUTH] %s\n", creds);
                db_insert_honeypot_log("SSH", ip, "AUTH", creds);
                db_insert_event(ip, 22, "SSH_LOGIN", "MEDIUM", "SSH_HONEYPOT_TRAP");

                ssh_message_auth_reply_success(message, 0);
                authenticated = 1;
            } else {
                ssh_message_auth_set_methods(message, SSH_AUTH_METHOD_PASSWORD);
                ssh_message_reply_default(message);
            }
        } else {
            ssh_message_reply_default(message);
        }
        ssh_message_free(message);
    }

    if (!authenticated) {
        ssh_disconnect(session);
        ssh_free(session);
        return NULL;
    }

    while (!chan && (message = ssh_message_get(session)) != NULL) {
        if (ssh_message_type(message) == SSH_REQUEST_CHANNEL_OPEN &&
            ssh_message_subtype(message) == SSH_CHANNEL_SESSION) {
            chan = ssh_message_channel_request_open_reply_accept(message);
        } else {
            ssh_message_reply_default(message);
        }
        ssh_message_free(message);
    }

    if (!chan) {
        ssh_disconnect(session);
        ssh_free(session);
        return NULL;
    }

    while (!shell_requested && (message = ssh_message_get(session)) != NULL) {
        if (ssh_message_type(message) == SSH_REQUEST_CHANNEL) {
            int sub = ssh_message_subtype(message);
            if (sub == SSH_CHANNEL_REQUEST_PTY) {
                ssh_message_channel_request_reply_success(message);
            } else if (sub == SSH_CHANNEL_REQUEST_SHELL) {
                ssh_message_channel_request_reply_success(message);
                shell_requested = 1;
            } else if (sub == SSH_CHANNEL_REQUEST_EXEC) {
                const char *exec_cmd = ssh_message_channel_request_command(message);
                ssh_message_channel_request_reply_success(message);
                if (exec_cmd) {
                    printf("[HONEYPOT-SSH] EXEC from %s (%s): %s\n", ip, username, exec_cmd);
                    log_ssh_file(ip, "[EXEC:%s] %s\n", username, exec_cmd);
                    db_insert_honeypot_log("SSH", ip, "EXEC", exec_cmd);
                    send_fake_command_output(chan, username, exec_cmd);
                }
                ssh_message_free(message);
                goto cleanup;
            } else {
                ssh_message_reply_default(message);
            }
        } else {
            ssh_message_reply_default(message);
        }
        ssh_message_free(message);
    }

    const char *welcome =
        "Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n\r\n"
        "Last login: Fri Nov 20 10:12:04 2026 from 192.168.1.1\r\n";
    ssh_channel_write(chan, welcome, (uint32_t)strlen(welcome));

    char prompt[160];
    snprintf(prompt, sizeof(prompt), "%s@ubuntu-prod:~# ", username);
    ssh_channel_write(chan, prompt, (uint32_t)strlen(prompt));

    char cmd_buf[512];
    size_t cmd_len = 0;
    unsigned char ch;
    int last_was_cr = 0;

    while (ssh_channel_is_open(chan) && !ssh_channel_is_eof(chan)) {
        int n = ssh_channel_read(chan, &ch, 1, 0);
        if (n <= 0) break;

        if (ch == '\n' && last_was_cr) {
            last_was_cr = 0;
            continue;
        }
        last_was_cr = (ch == '\r');

        log_raw_key(ip, username, ch);

        if (ch == '\r' || ch == '\n') {
            ssh_channel_write(chan, "\r\n", 2);
            cmd_buf[cmd_len] = '\0';

            if (cmd_len > 0) {
                printf("[HONEYPOT-SSH] %s (%s) ran: %s\n", ip, username, cmd_buf);
                log_ssh_file(ip, "[CMD:%s] %s\n", username, cmd_buf);
                db_insert_honeypot_log("SSH", ip, "CMD", cmd_buf);

                if (strcmp(cmd_buf, "exit") == 0 || strcmp(cmd_buf, "logout") == 0) {
                    ssh_channel_write(chan, "logout\r\n", 8);
                    break;
                }
                send_fake_command_output(chan, username, cmd_buf);
            }

            cmd_len = 0;
            ssh_channel_write(chan, prompt, (uint32_t)strlen(prompt));
        } else if (ch == 0x7f || ch == 0x08) {
            if (cmd_len > 0) {
                cmd_len--;
                ssh_channel_write(chan, "\b \b", 3);
            }
        } else if (ch == 0x03) {
            cmd_len = 0;
            ssh_channel_write(chan, "^C\r\n", 4);
            ssh_channel_write(chan, prompt, (uint32_t)strlen(prompt));
        } else if (ch == 0x04) {
            ssh_channel_write(chan, "logout\r\n", 8);
            break;
        } else if (isprint(ch)) {
            if (cmd_len < sizeof(cmd_buf) - 1) {
                cmd_buf[cmd_len++] = (char)ch;
            }
            ssh_channel_write(chan, &ch, 1);
        }
    }

cleanup:
    db_insert_honeypot_log("SSH", ip, "DISCONNECT", username);
    ssh_channel_send_eof(chan);
    ssh_channel_close(chan);
    ssh_channel_free(chan);
    ssh_disconnect(session);
    ssh_free(session);
    return NULL;
}

void* start_fake_ssh(void *arg) {
    (void)arg;
    ssh_init();

    ssh_bind sshbind = ssh_bind_new();
    if (!sshbind) return NULL;

    unsigned int port = HONEYPOT_SSH_PORT;
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &port);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_HOSTKEY, SSH_HOST_KEY_PATH);

    if (ssh_bind_listen(sshbind) < 0) {
        fprintf(stderr, "[HONEYPOT-SSH] Listen error: %s\n", ssh_get_error(sshbind));
        ssh_bind_free(sshbind);
        return NULL;
    }

    printf("[HONEYPOT] Fake SSH Keylogger Service listening on port %d\n", HONEYPOT_SSH_PORT);

    while (1) {
        ssh_session session = ssh_new();
        if (!session) continue;

        if (ssh_bind_accept(sshbind, session) == SSH_ERROR) {
            ssh_free(session);
            continue;
        }

        pthread_t tid;
        if (pthread_create(&tid, NULL, handle_ssh_client, session) == 0) {
            pthread_detach(tid);
        } else {
            ssh_disconnect(session);
            ssh_free(session);
        }
    }

    ssh_bind_free(sshbind);
    return NULL;
}