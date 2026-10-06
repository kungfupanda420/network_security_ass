-- database/schema.sql

CREATE TABLE IF NOT EXISTS attacks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    ip TEXT NOT NULL,
    target_port INTEGER NOT NULL,
    scan_type TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    action TEXT NOT NULL
);