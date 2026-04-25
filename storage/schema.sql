-- ==========================================
-- ARGUS Database Schema
-- ==========================================
-- SQLite with WAL mode for concurrency

PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

-- ------------------------------------------
-- Table: metrics
-- All system readings collected by monitor
-- ------------------------------------------
CREATE TABLE IF NOT EXISTS metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,

    -- Core metrics
    cpu_percent REAL NOT NULL,
    memory_percent REAL NOT NULL,
    memory_used_gb REAL NOT NULL,
    memory_total_gb REAL NOT NULL,
    disk_percent REAL NOT NULL,
    disk_free_gb REAL NOT NULL,
    process_count INTEGER NOT NULL,
    thread_count INTEGER NOT NULL,
    network_sent_mb REAL DEFAULT 0,
    network_recv_mb REAL DEFAULT 0,
    network_connections INTEGER DEFAULT 0,

    -- Enhanced features (for AI)
    cpu_delta REAL DEFAULT 0,              -- rate of change
    memory_delta REAL DEFAULT 0,
    process_spawn_rate REAL DEFAULT 0,     -- new processes per minute
    top_process_cpu_ratio REAL DEFAULT 0,  -- top process %
    disk_io_read_rate REAL DEFAULT 0,
    disk_io_write_rate REAL DEFAULT 0,
    context_switches_per_sec REAL DEFAULT 0,

    -- Time context
    hour_of_day INTEGER NOT NULL,
    day_of_week INTEGER NOT NULL,

    -- AI output
    is_anomaly INTEGER DEFAULT 0,
    anomaly_score REAL DEFAULT 0.0,
    ai_explanation TEXT                    -- SHAP feature contributions JSON
);

CREATE INDEX IF NOT EXISTS idx_metrics_time ON metrics(timestamp);
CREATE INDEX IF NOT EXISTS idx_metrics_anomaly ON metrics(is_anomaly);

-- ------------------------------------------
-- Table: events
-- All log entries
-- ------------------------------------------
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    level TEXT NOT NULL,              -- INFO, WARN, CRITICAL, ACTION, SECURITY
    category TEXT NOT NULL,           -- cpu, memory, disk, service, ai, security
    message TEXT NOT NULL,
    source TEXT NOT NULL,             -- rules, ai, manual, watcher
    metadata TEXT                     -- JSON for extra context
);

CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_level ON events(level);
CREATE INDEX IF NOT EXISTS idx_events_category ON events(category);

-- ------------------------------------------
-- Table: actions
-- Remediation actions taken
-- ------------------------------------------
CREATE TABLE IF NOT EXISTS actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    action_type TEXT NOT NULL,        -- kill_process, clear_temp, alert, etc.
    target TEXT,                      -- process name, folder path
    trigger TEXT NOT NULL,            -- rule, ai, hybrid, manual
    success INTEGER NOT NULL,
    details TEXT,
    reversed INTEGER DEFAULT 0        -- was this action undone?
);

CREATE INDEX IF NOT EXISTS idx_actions_time ON actions(timestamp);

-- ------------------------------------------
-- Table: attacks
-- Attack simulation history
-- ------------------------------------------
CREATE TABLE IF NOT EXISTS attacks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    attack_type TEXT NOT NULL,
    parameters TEXT,                  -- JSON
    duration_seconds INTEGER DEFAULT 0,
    stopped_by TEXT,                  -- user, timeout, kill_switch, defender, error
    detected_by_defender INTEGER DEFAULT 0,
    detection_latency_seconds REAL,   -- how fast was defender?
    pid INTEGER                       -- attacker process PID (for whitelist)
);

CREATE INDEX IF NOT EXISTS idx_attacks_time ON attacks(timestamp);

-- ------------------------------------------
-- Table: custom_rules
-- User-defined rules
-- ------------------------------------------
CREATE TABLE IF NOT EXISTS custom_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    metric TEXT NOT NULL,             -- cpu, memory, disk, processes, custom
    operator TEXT NOT NULL,           -- >, <, >=, <=, ==
    threshold REAL NOT NULL,
    duration_seconds INTEGER DEFAULT 0,
    action TEXT NOT NULL,             -- kill_top, clear_temp, alert_only
    severity TEXT DEFAULT 'warning',  -- info, warning, critical
    enabled INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ------------------------------------------
-- Table: feedback
-- User corrections (false positive / false negative)
-- ------------------------------------------
CREATE TABLE IF NOT EXISTS feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    metric_id INTEGER,                -- links to metrics.id
    feedback_type TEXT NOT NULL,      -- false_positive, false_negative, correct
    note TEXT,
    applied_to_training INTEGER DEFAULT 0,
    FOREIGN KEY(metric_id) REFERENCES metrics(id)
);

-- ------------------------------------------
-- Table: process_genealogy
-- Parent-child process tracking (security)
-- ------------------------------------------
CREATE TABLE IF NOT EXISTS process_genealogy (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    pid INTEGER NOT NULL,
    parent_pid INTEGER,
    process_name TEXT NOT NULL,
    parent_name TEXT,
    cmdline TEXT,
    is_suspicious INTEGER DEFAULT 0,
    suspicious_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_genealogy_time ON process_genealogy(timestamp);
CREATE INDEX IF NOT EXISTS idx_genealogy_suspicious ON process_genealogy(is_suspicious);

-- ------------------------------------------
-- Table: network_connections
-- Network watcher log
-- ------------------------------------------
CREATE TABLE IF NOT EXISTS network_connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    pid INTEGER,
    process_name TEXT,
    local_address TEXT,
    local_port INTEGER,
    remote_address TEXT,
    remote_port INTEGER,
    status TEXT,
    is_suspicious INTEGER DEFAULT 0,
    suspicious_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_netconn_time ON network_connections(timestamp);

-- ------------------------------------------
-- Table: file_integrity
-- File integrity monitoring
-- ------------------------------------------
CREATE TABLE IF NOT EXISTS file_integrity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_path TEXT NOT NULL UNIQUE,
    hash_sha256 TEXT NOT NULL,
    size_bytes INTEGER,
    last_modified DATETIME,
    last_checked DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ------------------------------------------
-- Table: registry_snapshot
-- Track registry changes (Windows persistence)
-- ------------------------------------------
CREATE TABLE IF NOT EXISTS registry_snapshot (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    registry_key TEXT NOT NULL,
    value_name TEXT,
    value_data TEXT,
    change_type TEXT                  -- added, removed, modified
);

CREATE INDEX IF NOT EXISTS idx_registry_time ON registry_snapshot(timestamp);

-- ------------------------------------------
-- Table: usb_events
-- USB device plug/unplug log
-- ------------------------------------------
CREATE TABLE IF NOT EXISTS usb_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    event_type TEXT NOT NULL,         -- connected, disconnected
    device_id TEXT,
    device_name TEXT,
    drive_letter TEXT
);
