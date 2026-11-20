#ifndef DB_SQLITE_H
#define DB_SQLITE_H

#include <stdint.h>

int db_init(const char *db_path);
int db_insert_event(const char *ip_str, uint16_t target_port, const char *scan_type, const char *risk_level, const char *action);
int db_insert_honeypot_log(const char *service, const char *ip_str, const char *event_type, const char *details);
int db_insert_keystroke(const char *ip_str, const char *username, const char *keystroke);

#endif