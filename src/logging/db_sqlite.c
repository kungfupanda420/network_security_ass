#include "db_sqlite.h"
#include <stdio.h>
#include <sqlite3.h>

static sqlite3 *db;

int db_init(const char *db_path) {
    int rc = sqlite3_open(db_path, &db);
    if (rc) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return 0;
    }

    // Updated to include target_port INTEGER
    const char *sql = "CREATE TABLE IF NOT EXISTS attacks ("
                      "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                      "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,"
                      "ip TEXT,"
                      "target_port INTEGER,"
                      "scan_type TEXT,"
                      "risk_level TEXT,"
                      "action TEXT);";

    char *err_msg = NULL;
    rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        return 0;
    }
    
    return 1;
}

int db_insert_event(const char *ip_str, uint16_t target_port, const char *scan_type, const char *risk_level, const char *action) {
    if (!db) return 0;

    char sql[512];
    // Updated to format target_port into the SQL query
    snprintf(sql, sizeof(sql), 
             "INSERT INTO attacks (ip, target_port, scan_type, risk_level, action) VALUES ('%s', %u, '%s', '%s', '%s');", 
             ip_str, target_port, scan_type, risk_level, action);

    char *err_msg = NULL;
    int rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to insert into DB: %s\n", err_msg);
        sqlite3_free(err_msg);
        return 0;
    }
    
    return 1;
}