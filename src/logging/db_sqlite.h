#ifndef DB_SQLITE_H
#define DB_SQLITE_H

#include <stdint.h>

int db_init(const char *db_path);

// Added target_port
int db_insert_event(const char *ip_str, uint16_t target_port, const char *scan_type, const char *risk_level, const char *action);

#endif