#include "logger.h"
#include "db_sqlite.h"
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/types.h>

#define DB_PATH "database/alerts.db"

void logger_init() {
    // Ensure the database directory exists (permissions 0777)
    mkdir("database", 0777); 

    if (db_init(DB_PATH)) {
        printf("[SYSTEM] SQLite Database initialized at %s\n", DB_PATH);
    } else {
        printf("[SYSTEM] Failed to initialize database!\n");
    }
}

void log_attack_event(uint32_t ip_addr, uint16_t dest_port, const char *scan_type, int risk_tier, const char *action_taken) {
    struct in_addr ip_struct;
    ip_struct.s_addr = ip_addr;
    const char *ip_str = inet_ntoa(ip_struct);

    const char *risk_str = "UNKNOWN";
    if (risk_tier == 1) risk_str = "LOW";
    else if (risk_tier == 2) risk_str = "MEDIUM";
    else if (risk_tier == 3) risk_str = "HIGH";

    // Pass dest_port down to the database module
    db_insert_event(ip_str, dest_port, scan_type, risk_str, action_taken);
}