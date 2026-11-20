#include "db_sqlite.h"
#include <stdio.h>
#include <pthread.h>
#include <sqlite3.h>

static sqlite3 *db = NULL;
static pthread_mutex_t db_mutex = PTHREAD_MUTEX_INITIALIZER;

int db_init(const char *db_path) {
    pthread_mutex_lock(&db_mutex);

    int rc = sqlite3_open(db_path, &db);
    if (rc) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        pthread_mutex_unlock(&db_mutex);
        return 0;
    }

    // Prevent "database is locked" during concurrent C writes + Flask reads
    sqlite3_exec(db, "PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;", 0, 0, NULL);

    const char *sql =
        "CREATE TABLE IF NOT EXISTS attacks ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,"
        "ip TEXT,"
        "target_port INTEGER,"
        "scan_type TEXT,"
        "risk_level TEXT,"
        "action TEXT);"

        "CREATE TABLE IF NOT EXISTS honeypot_logs ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,"
        "service TEXT,"
        "ip TEXT,"
        "event_type TEXT,"
        "details TEXT);"

        "CREATE TABLE IF NOT EXISTS ssh_keystrokes ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,"
        "ip TEXT,"
        "username TEXT,"
        "keystroke TEXT);";

    char *err_msg = NULL;
    rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        pthread_mutex_unlock(&db_mutex);
        return 0;
    }

    pthread_mutex_unlock(&db_mutex);
    return 1;
}

int db_insert_event(const char *ip_str, uint16_t target_port, const char *scan_type, const char *risk_level, const char *action) {
    pthread_mutex_lock(&db_mutex);
    if (!db) {
        pthread_mutex_unlock(&db_mutex);
        return 0;
    }

    const char *sql =
        "INSERT INTO attacks (ip, target_port, scan_type, risk_level, action) "
        "VALUES (?, ?, ?, ?, ?);";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&db_mutex);
        return 0;
    }

    sqlite3_bind_text(stmt, 1, ip_str, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, (int)target_port);
    sqlite3_bind_text(stmt, 3, scan_type, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, risk_level, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, action, -1, SQLITE_TRANSIENT);

    int ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&db_mutex);
    return ok;
}

int db_insert_honeypot_log(const char *service, const char *ip_str, const char *event_type, const char *details) {
    pthread_mutex_lock(&db_mutex);
    if (!db) {
        pthread_mutex_unlock(&db_mutex);
        return 0;
    }

    const char *sql =
        "INSERT INTO honeypot_logs (service, ip, event_type, details) "
        "VALUES (?, ?, ?, ?);";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&db_mutex);
        return 0;
    }

    sqlite3_bind_text(stmt, 1, service, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, ip_str, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, event_type, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, details ? details : "", -1, SQLITE_TRANSIENT);

    int ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&db_mutex);
    return ok;
}

int db_insert_keystroke(const char *ip_str, const char *username, const char *keystroke) {
    pthread_mutex_lock(&db_mutex);
    if (!db) {
        pthread_mutex_unlock(&db_mutex);
        return 0;
    }

    const char *sql =
        "INSERT INTO ssh_keystrokes (ip, username, keystroke) "
        "VALUES (?, ?, ?);";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&db_mutex);
        return 0;
    }

    sqlite3_bind_text(stmt, 1, ip_str, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, username, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, keystroke, -1, SQLITE_TRANSIENT);

    int ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&db_mutex);
    return ok;
}