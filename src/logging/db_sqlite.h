#ifndef DB_SQLITE_H
#define DB_SQLITE_H

// Initializes the SQLite database and creates tables if they don't exist
int db_init(const char *db_path);

// Inserts an attack record into the database
int db_insert_event(const char *ip_str, const char *scan_type, const char *risk_level, const char *action);

#endif