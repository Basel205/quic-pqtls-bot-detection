-- ════════════════════════════════════════════════════════════════════════════
-- Bot Detection System — SQLite Schema
-- ════════════════════════════════════════════════════════════════════════════
PRAGMA journal_mode = WAL;   -- Write-Ahead Logging: concurrent reads during writes
PRAGMA foreign_keys = ON;

-- ── Sessions ────────────────────────────────────────────────────────────────
-- One row per captured session (from session_orchestrator.py manifest)
CREATE TABLE IF NOT EXISTS sessions (
    session_id    TEXT PRIMARY KEY,
    label         TEXT NOT NULL,          -- human / bot_t1 / bot_t2 / bot_t3 / bot_t4
    source        TEXT,                   -- playwright_chrome / requests / curl_impersonate / etc.
    start_ts      REAL NOT NULL,          -- Unix timestamp (float)
    end_ts        REAL,
    pcap_path     TEXT                    -- path to the session's pcap file
);

-- ── Features ────────────────────────────────────────────────────────────────
-- One row per session: the 19-field feature vector (mirrors feature_schema.py)
CREATE TABLE IF NOT EXISTS features (
    session_id                TEXT PRIMARY KEY REFERENCES sessions(session_id),
    ja4_fingerprint_hash      INTEGER,
    tls_version               INTEGER,
    cipher_suite_count        INTEGER,
    cipher_suite_order_hash   INTEGER,
    extension_count           INTEGER,
    extension_order_hash      INTEGER,
    supported_groups_hash     INTEGER,
    alpn_hash                 INTEGER,
    has_pq_keyshare           INTEGER DEFAULT 0,   -- 0/1
    pq_keyshare_data_len      INTEGER DEFAULT -1,  -- -1 = absent
    used_http3                INTEGER DEFAULT 0,
    quic_version              INTEGER DEFAULT -1,
    quic_transport_param_count INTEGER DEFAULT -1,
    quic_conn_id_len          INTEGER DEFAULT -1,
    inter_request_timing_cv   REAL DEFAULT 0.0,
    record_layer_timing_p50   REAL DEFAULT 0.0,
    session_request_count     INTEGER DEFAULT 0,
    ja4h_fingerprint_hash     INTEGER DEFAULT 0,
    extracted_at              REAL DEFAULT (unixepoch('now', 'subsec'))
);

-- ── Live Events ─────────────────────────────────────────────────────────────
-- Written by the live detection proxy in real time
CREATE TABLE IF NOT EXISTS live_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              REAL NOT NULL DEFAULT (unixepoch('now', 'subsec')),
    client_ip       TEXT,
    client_port     INTEGER,
    protocol        TEXT,                -- tcp_tls / quic
    ja4_hash        TEXT,
    has_pq          INTEGER,
    used_quic       INTEGER,
    ml_score        REAL,                -- raw probability of being human
    ml_label        TEXT,                -- predicted class
    decision        TEXT NOT NULL,       -- allow / block
    latency_ms      REAL                 -- end-to-end scoring latency
);

-- Index for dashboard queries
CREATE INDEX IF NOT EXISTS idx_live_events_ts ON live_events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_live_events_decision ON live_events(decision);

-- ── Model Runs ──────────────────────────────────────────────────────────────
-- Snapshot of each ML training run (mirrors MLflow, but local for dashboard)
CREATE TABLE IF NOT EXISTS model_runs (
    run_id          TEXT PRIMARY KEY,
    experiment_name TEXT,
    accuracy        REAL,
    macro_f1        REAL,
    roc_auc         REAL,
    trained_at      REAL DEFAULT (unixepoch('now', 'subsec')),
    model_path      TEXT
);
