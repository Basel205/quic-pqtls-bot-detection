# System Design & Architecture Brief (COMPLETE, CORRECTED)
## QUIC + PQ-TLS Bot Detection — Exact Execution Instructions

> **This document is fully self-contained. It replaces all earlier versions of the system design brief. Do not reference or fall back to any prior version.**

> **CHANGELOG FROM THE ORIGINAL BRIEF — read this first, and reconcile against any files already written:**
> 1. **Caddyfile (Section 3.1):** Removed the explicit `curves` directive entirely. The original specified `x25519_kyber768draft00`, a retired, deprecated group name that Go's TLS stack has been phasing out since version 1.23. Critically, explicitly setting a `curves` list without including `x25519mlkem768` **disables Caddy's default post-quantum support entirely** — confirmed directly against Caddy's own documentation. Caddy 2.10+ enables `X25519MLKEM768` by default with zero configuration, so the fix is to specify nothing and let the default apply.
> 2. **`feature_schema.py` (Section 3.4):** `PQ_GROUP_ID` corrected from `0x6399` to `0x11EC` (4588 decimal) — the actual IANA-registered codepoint for `X25519MLKEM768`. `0x6399` was the retired draft codepoint (`X25519Kyber768Draft00`), superseded and no longer sent by current browsers.
> 3. **`pq_detector.py` (Section 4.2):** Same correction — `0x11EC`, not `0x6399`.
> 4. **Gate 1 smoke test (Section 7):** The original PowerShell command accepted `kyber`/`6399` matches as a pass — these are now treated as a failure signal. Also fixed invalid regex escaping (`\|` is bash/grep syntax, not valid .NET regex alternation for PowerShell's `Select-String`, which uses a bare `|`).
> 5. **Added:** full content for `run_all.ps1`, `target-site/package.json`, and `db/init_db.py`, which were named in the original brief but never actually specified.
>
> **If `Caddyfile`, `feature_schema.py`, or `pq_detector.py` already exist in the repo from an earlier version, open them now and check directly against Sections 3.1, 3.4, and 4.2 before running any smoke test.**

---

## System Context

**Environment confirmed:**
- OS: Windows 11
- Node.js: v22.14.0
- Python: 3.11.6
- Caddy: install per Section 1 — **must be v2.10.0 or later** (the version that added ML-KEM support by default)
- tshark: install per Section 1

**Proxy strategy (the key architectural decision):**

The TLS ClientHello is sent by the client in plaintext before any encryption begins. Our proxy reads raw TCP bytes before performing any TLS handshake, extracts the ClientHello, scores it, and either forwards the raw stream to Caddy or drops the connection. This means:
- No certificate management for the proxy
- Zero TLS overhead in the proxy itself
- Sub-20ms feature extraction from raw bytes

QUIC runs over UDP. Our TCP proxy cannot intercept UDP. QUIC sessions are captured passively by tshark and scored asynchronously (~1s delay). The dashboard shows both TCP-intercepted and QUIC-passively-scored events.

---

## Section 1 — Installation Instructions

### 1.1 Install Caddy (Windows)

```powershell
Invoke-WebRequest -Uri "https://github.com/caddyserver/caddy/releases/latest/download/caddy_windows_amd64.zip" -OutFile "$env:USERPROFILE\Downloads\caddy.zip"
Expand-Archive "$env:USERPROFILE\Downloads\caddy.zip" -DestinationPath "C:\caddy"
[Environment]::SetEnvironmentVariable("PATH", $env:PATH + ";C:\caddy", "Machine")
# Restart PowerShell, then verify:
caddy version
```

Confirm the version is 2.10.0 or later. If older, download the latest release explicitly — do not proceed with an older version, since default PQ support depends on it.

### 1.2 Install Wireshark + tshark (Windows)

Download from https://www.wireshark.org/download.html. During installation, check **"Install TShark"** and also install **Npcap** (required for loopback capture on Windows).

```powershell
[Environment]::SetEnvironmentVariable("PATH", $env:PATH + ";C:\Program Files\Wireshark", "Machine")
# Restart PowerShell, then verify:
tshark --version
tshark -D
# Note the loopback adapter name, typically: 4. \Device\NPF_Loopback
```

### 1.3 Python Virtual Environment

```powershell
cd C:\Users\kbase\Projects\quic-pqtls-bot-detection
python -m venv .venv
.\.venv\Scripts\Activate.ps1

pip install playwright scapy pyarrow pandas mlflow xgboost catboost scikit-learn shap fastapi uvicorn websockets httpx requests aioquic joblib ruff pytest

playwright install chromium firefox
```

### 1.4 Node.js Dependencies

```powershell
# In target-site/ directory
cd target-site
npm install
```

### 1.5 Trust Caddy's Local CA

```powershell
caddy trust
```

Run once. Installs Caddy's auto-generated CA into the Windows/Chrome/Firefox trust stores.

### 1.6 Verification Checklist

Run these before writing any code and confirm all pass:

```powershell
caddy version          # v2.10.0 or higher — REQUIRED
tshark --version       # TShark 4.x.x
python --version       # Python 3.11.6
node --version         # v22.14.0
playwright --version   # Version 1.x.x
```

---

## Section 2 — Repository Scaffold

Create this exact directory and file structure. Create all files not marked "WRITE THIS FULLY" as empty stubs first, then fill in per Sections 3 and 4.

```
quic-pqtls-bot-detection/
│
├── .gitignore                        ← Section 8
├── README.md
├── requirements.txt                  ← Section 9
├── docker-compose.yml                (stub, optional — Windows uses run_all.ps1)
├── run_all.ps1                       ← Section 9.1
│
├── target-site/
│   ├── Caddyfile                     ← Section 3.1
│   ├── package.json                  ← Section 9.2
│   ├── server.js                     ← Section 3.2
│   └── public/
│       ├── index.html
│       ├── products.html
│       ├── search.html
│       ├── login.html
│       └── style.css
│
├── traffic-gen/
│   ├── __init__.py
│   ├── config.py                     ← Section 3.3
│   ├── human_traffic.py
│   ├── bot_tier1_naive.py
│   ├── bot_tier2_evasive.py
│   ├── bot_tier3_sophisticated.py
│   ├── bot_tier4_adaptive.py
│   └── session_orchestrator.py
│
├── capture/
│   ├── __init__.py
│   ├── capture_sidecar.py            ← Section 4.1
│   └── pcap_store/
│       └── .gitkeep
│
├── feature-extraction/
│   ├── __init__.py
│   ├── feature_schema.py             ← Section 3.4
│   ├── ja4_extractor.py
│   ├── ja4h_extractor.py
│   ├── pq_detector.py                ← Section 4.2
│   ├── quic_parser.py                ← Section 4.3
│   ├── timing_extractor.py           ← Section 4.4
│   └── build_dataset.py
│
├── ml/
│   ├── __init__.py
│   ├── config.py                     ← Section 3.5
│   ├── train_baseline.py
│   ├── train_enhanced.py
│   ├── evaluate.py
│   ├── evasion_test.py
│   ├── feature_importance.py
│   └── model_registry/
│       └── .gitkeep
│
├── detection-service/
│   ├── __init__.py
│   ├── proxy.py                      ← Section 4.5
│   ├── feature_realtime.py
│   ├── scorer.py
│   └── api.py                        ← Section 4.6
│
├── dashboard/
│   ├── index.html
│   ├── package.json
│   ├── vite.config.js
│   └── src/
│       ├── main.jsx
│       ├── App.jsx
│       ├── index.css
│       ├── components/
│       │   ├── LiveFeed.jsx
│       │   ├── StatsCards.jsx
│       │   ├── AccuracyChart.jsx
│       │   ├── BlockRateChart.jsx
│       │   └── FingerprintCard.jsx
│       └── hooks/
│           └── useWebSocket.js
│
├── db/
│   ├── schema.sql                    ← Section 3.6
│   └── init_db.py                    ← Section 9.3
│
├── tests/
│   ├── __init__.py
│   ├── fixtures/
│   │   └── README.md                 (explains how fixtures are generated)
│   ├── test_feature_extraction.py
│   ├── test_scorer.py
│   └── test_proxy.py
│
└── notebooks/
    ├── 01_dataset_eda.ipynb
    └── 02_results_visualization.ipynb
```

---

## Section 3 — Files to Write Fully First (Foundations)

These files must be written completely before anything else. Everything else depends on them.

---

### 3.1 `target-site/Caddyfile`

```caddyfile
{
    local_certs
    auto_https off
}

localhost:443 {
    tls internal
    # NOTE: No explicit `curves` directive here, deliberately.
    # Caddy 2.10+ defaults to X25519MLKEM768, X25519, P-256, P-384
    # automatically. Explicitly listing curves would OVERRIDE that
    # default and could disable post-quantum support entirely unless
    # x25519mlkem768 is included in the list — so we rely on the default
    # instead of hand-specifying it.

    reverse_proxy localhost:3000

    log {
        output file ./logs/access.log
        format json
    }
}
```

**Verify independently of the browser after starting Caddy:**
```powershell
openssl s_client -connect localhost:443 -groups X25519MLKEM768 -brief
# Expected output includes: Negotiated TLS1.3 group: X25519MLKEM768
```

---

### 3.2 `target-site/server.js`

```javascript
const express = require('express');
const helmet = require('helmet');
const morgan = require('morgan');
const app = express();

app.use(helmet({ contentSecurityPolicy: false }));
app.use(morgan('combined'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// ── Routes ──────────────────────────────────────────────

app.get('/', (req, res) => res.sendFile('index.html', { root: './public' }));

const PRODUCTS = Array.from({ length: 100 }, (_, i) => ({
    id: i + 1,
    name: `Product ${i + 1}`,
    price: (Math.random() * 500 + 10).toFixed(2),
    category: ['electronics', 'books', 'clothing', 'sports'][i % 4],
}));

app.get('/api/products', (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const start = (page - 1) * limit;
    res.json({
        products: PRODUCTS.slice(start, start + limit),
        total: PRODUCTS.length,
        page,
        pages: Math.ceil(PRODUCTS.length / limit),
    });
});

app.get('/api/search', (req, res) => {
    const q = (req.query.q || '').toLowerCase();
    const results = PRODUCTS.filter(p => p.name.toLowerCase().includes(q));
    res.json({ results, count: results.length });
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Missing credentials' });
    }
    res.json({ token: 'fake-jwt-token', user: { id: 1, username } });
});

app.get('/api/profile', (req, res) => {
    const auth = req.headers['authorization'];
    if (!auth) return res.status(401).json({ error: 'Unauthorized' });
    res.json({ id: 1, username: 'testuser', plan: 'premium' });
});

app.get('/health', (req, res) => res.json({ status: 'ok' }));

const PORT = 3000;
app.listen(PORT, () => console.log(`Target site running on http://localhost:${PORT}`));
```

---

### 3.3 `traffic-gen/config.py`

```python
"""
Central configuration for all traffic generation components.
All other traffic-gen scripts import from here — change values here only.
"""
from pathlib import Path

# ── Paths ────────────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).parent.parent
PCAP_STORE   = PROJECT_ROOT / "capture" / "pcap_store"
DB_PATH      = PROJECT_ROOT / "db" / "bot_detection.db"
DATASET_PATH = PROJECT_ROOT / "feature-extraction" / "dataset.parquet"
MANIFEST_PATH = PROJECT_ROOT / "traffic-gen" / "session_manifest.csv"

# ── Target site ──────────────────────────────────────────────────────────────
TARGET_BASE_URL = "https://localhost:443"
TARGET_PAGES = [
    "/",
    "/api/products?page=1",
    "/api/products?page=2",
    "/api/search?q=electronics",
    "/api/login",
    "/api/profile",
]

# ── Timing (seconds) ─────────────────────────────────────────────────────────
HUMAN_DELAY_MEAN   = 2.5
HUMAN_DELAY_STD    = 1.2
HUMAN_SESSION_REQS = (5, 15)

BOT_DELAY_MEAN     = 0.05
BOT_DELAY_STD      = 0.01

# ── Session targets ──────────────────────────────────────────────────────────
SESSIONS_HUMAN  = 500
SESSIONS_TIER1  = 400
SESSIONS_TIER2  = 400
SESSIONS_TIER3  = 300
SESSIONS_TIER4  = 200  # Evasion bots — run separately after model is trained

# ── Capture ──────────────────────────────────────────────────────────────────
# Run `tshark -D` on your machine and confirm the loopback adapter number/name
TSHARK_INTERFACE = r"\Device\NPF_Loopback"  # confirm via tshark -D
TSHARK_PORT      = 443
TSHARK_BIN       = r"C:\Program Files\Wireshark\tshark.exe"

# ── ML ───────────────────────────────────────────────────────────────────────
RANDOM_SEED  = 42
TEST_SIZE    = 0.15
VAL_SIZE     = 0.15
MLFLOW_URI   = "sqlite:///mlflow.db"

# ── Detection proxy ──────────────────────────────────────────────────────────
PROXY_LISTEN_HOST = "127.0.0.1"
PROXY_LISTEN_PORT = 8443
CADDY_FORWARD_HOST = "127.0.0.1"
CADDY_FORWARD_PORT = 443
SCORE_THRESHOLD   = 0.5   # score > 0.5 → human; else → bot

# ── API ──────────────────────────────────────────────────────────────────────
API_HOST = "127.0.0.1"
API_PORT = 8000
```

---

### 3.4 `feature-extraction/feature_schema.py`

```python
"""
Canonical feature schema for the bot detection classifier.
This is the SINGLE SOURCE OF TRUTH for feature names, types, and nullability.
Both the training pipeline and the real-time proxy use this schema.
Any change here must be reflected in both.
"""
from dataclasses import dataclass
from typing import Optional, List

# ── PQ Key Share ─────────────────────────────────────────────────────────────
# X25519MLKEM768 group ID as registered by IANA: 0x11EC (4588 decimal).
# This is the FINAL, STANDARDIZED codepoint — used by current Chrome, Firefox,
# and Caddy 2.10+ by default as of 2025-2026.
#
# DO NOT use 0x6399 — that is X25519Kyber768Draft00, a retired
# pre-standardization draft codepoint used experimentally by Chrome/Edge in
# 2023-2024. It is superseded and no longer sent by current browsers.
# Checking for 0x6399 will silently fail to detect real, current
# post-quantum traffic and invalidate the entire core result of this project.
PQ_GROUP_ID = 0x11EC

# ── Feature Names ────────────────────────────────────────────────────────────
CLASSICAL_FEATURES = [
    "ja4_fingerprint_hash",    # int (hashed for ML)
    "tls_version",             # int (771=TLS1.3, etc.)
    "cipher_suite_count",      # int
    "cipher_suite_order_hash", # int (hashed)
    "extension_count",         # int
    "extension_order_hash",    # int (hashed)
    "supported_groups_hash",   # int (hashed multi-hot)
    "alpn_hash",               # int (hashed ALPN list)
]

NEW_PROTOCOL_FEATURES = [
    "has_pq_keyshare",         # bool (0/1) — CORE NOVEL SIGNAL, check group 0x11EC
    "pq_keyshare_data_len",    # int (nullable → -1 if absent; expect ~1216 bytes when present)
    "used_http3",              # bool (0/1) — CORE NOVEL SIGNAL
    "quic_version",            # int (nullable → -1 if no QUIC)
    "quic_transport_param_count",  # int (nullable → -1)
    "quic_conn_id_len",        # int (nullable → -1)
]

BEHAVIORAL_FEATURES = [
    "inter_request_timing_cv",  # float — coefficient of variation of inter-req gaps
    "record_layer_timing_p50",  # float (ms) — median TLS record timing
    "session_request_count",    # int — total requests in session
    "ja4h_fingerprint_hash",    # int (hashed HTTP fingerprint)
]

ALL_FEATURES = CLASSICAL_FEATURES + NEW_PROTOCOL_FEATURES + BEHAVIORAL_FEATURES
LABEL_COL    = "label"
SESSION_ID_COL = "session_id"

# Experiment feature sets (used by ml/config.py)
EXPERIMENT_A_FEATURES = CLASSICAL_FEATURES                            # Baseline
EXPERIMENT_B_FEATURES = ALL_FEATURES                                  # Enhanced
EXPERIMENT_C_FEATURES = CLASSICAL_FEATURES + NEW_PROTOCOL_FEATURES    # Ablation (isolates PQ/QUIC from timing)

# ── Label Encoding ───────────────────────────────────────────────────────────
LABEL_MAP = {
    "human":   0,
    "bot_t1":  1,
    "bot_t2":  2,
    "bot_t3":  3,
    "bot_t4":  4,   # evasion tier
}
LABEL_MAP_INV = {v: k for k, v in LABEL_MAP.items()}

# Binary collapse: human vs. any bot
BINARY_LABEL_MAP = {
    "human":   0,
    "bot_t1":  1,
    "bot_t2":  1,
    "bot_t3":  1,
    "bot_t4":  1,
}


@dataclass
class FeatureVector:
    """
    One row in the training dataset.
    All nullable fields default to their sentinel value (-1 or 0.0).
    The ML pipeline should treat -1 as NaN and use XGBoost's native NaN handling.
    """
    session_id: str

    # Classical TLS
    ja4_fingerprint_hash: int       = 0
    tls_version: int                = 0
    cipher_suite_count: int         = 0
    cipher_suite_order_hash: int    = 0
    extension_count: int            = 0
    extension_order_hash: int       = 0
    supported_groups_hash: int      = 0
    alpn_hash: int                  = 0

    # Novel signals
    has_pq_keyshare: int            = 0      # 0 or 1
    pq_keyshare_data_len: int       = -1     # -1 = absent
    used_http3: int                 = 0      # 0 or 1
    quic_version: int               = -1     # -1 = no QUIC
    quic_transport_param_count: int = -1
    quic_conn_id_len: int           = -1

    # Behavioral
    inter_request_timing_cv: float  = 0.0
    record_layer_timing_p50: float  = 0.0
    session_request_count: int      = 0
    ja4h_fingerprint_hash: int      = 0

    label: str                      = ""     # human / bot_t1 / bot_t2 / bot_t3 / bot_t4

    def to_dict(self) -> dict:
        from dataclasses import asdict
        return asdict(self)
```

---

### 3.5 `ml/config.py`

```python
"""
ML pipeline configuration. All training scripts import constants from here.
Change hyperparameters and feature sets here only.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from feature_extraction.feature_schema import (
    EXPERIMENT_A_FEATURES,
    EXPERIMENT_B_FEATURES,
    EXPERIMENT_C_FEATURES,
    LABEL_COL,
    SESSION_ID_COL,
    LABEL_MAP,
    BINARY_LABEL_MAP,
)
from traffic_gen.config import (
    DATASET_PATH,
    RANDOM_SEED,
    TEST_SIZE,
    VAL_SIZE,
    MLFLOW_URI,
)

# ── Experiment definitions ────────────────────────────────────────────────────
EXPERIMENTS = {
    "A_baseline": {
        "features":     EXPERIMENT_A_FEATURES,
        "description":  "Classical TLS features only (JA4 + cipher/extension metadata)",
    },
    "B_enhanced": {
        "features":     EXPERIMENT_B_FEATURES,
        "description":  "All features including PQ key-share, QUIC, and behavioral",
    },
    "C_ablation": {
        "features":     EXPERIMENT_C_FEATURES,
        "description":  "Classical + PQ/QUIC signals, no behavioral timing features",
    },
}

# ── Model hyperparameters ────────────────────────────────────────────────────
XGBOOST_PARAMS = {
    "n_estimators":     300,
    "max_depth":        6,
    "learning_rate":    0.05,
    "subsample":        0.8,
    "colsample_bytree": 0.8,
    "use_label_encoder": False,
    "eval_metric":      "mlogloss",
    "random_state":     RANDOM_SEED,
    "n_jobs":           -1,
}

CATBOOST_PARAMS = {
    "iterations":       300,
    "depth":            6,
    "learning_rate":    0.05,
    "random_seed":      RANDOM_SEED,
    "verbose":          0,
}

# ── Output paths ─────────────────────────────────────────────────────────────
MODEL_REGISTRY = Path(__file__).parent / "model_registry"
RESULTS_DIR    = Path(__file__).parent / "results"
RESULTS_DIR.mkdir(exist_ok=True)
```

---

### 3.6 `db/schema.sql`

```sql
-- ════════════════════════════════════════════════════════════════════════════
-- Bot Detection System — SQLite Schema
-- ════════════════════════════════════════════════════════════════════════════
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- ── Sessions ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sessions (
    session_id    TEXT PRIMARY KEY,
    label         TEXT NOT NULL,          -- human / bot_t1 / bot_t2 / bot_t3 / bot_t4
    source        TEXT,                   -- playwright_chrome / requests / curl_impersonate / etc.
    start_ts      REAL NOT NULL,
    end_ts        REAL,
    pcap_path     TEXT
);

-- ── Features ────────────────────────────────────────────────────────────────
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
    has_pq_keyshare           INTEGER DEFAULT 0,
    pq_keyshare_data_len      INTEGER DEFAULT -1,
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
CREATE TABLE IF NOT EXISTS live_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              REAL NOT NULL DEFAULT (unixepoch('now', 'subsec')),
    client_ip       TEXT,
    client_port     INTEGER,
    protocol        TEXT,                -- tcp_tls / quic
    ja4_hash        TEXT,
    has_pq          INTEGER,
    used_quic       INTEGER,
    ml_score        REAL,
    ml_label        TEXT,
    decision        TEXT NOT NULL,       -- allow / block
    latency_ms      REAL
);

CREATE INDEX IF NOT EXISTS idx_live_events_ts ON live_events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_live_events_decision ON live_events(decision);

-- ── Model Runs ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS model_runs (
    run_id          TEXT PRIMARY KEY,
    experiment_name TEXT,
    accuracy        REAL,
    macro_f1        REAL,
    roc_auc         REAL,
    trained_at      REAL DEFAULT (unixepoch('now', 'subsec')),
    model_path      TEXT
);
```

---

## Section 4 — Component Interfaces (Stubs to Implement)

These are the exact function signatures for every core file. Implement each function body; do not rename functions or change signatures.

---

### 4.1 `capture/capture_sidecar.py`

```python
"""
Wraps tshark to capture one pcap per session.
Called by session_orchestrator.py around each traffic generation run.
"""
import subprocess
import time
from pathlib import Path

def start_capture(session_id: str, pcap_dir: Path, interface: str, port: int, tshark_bin: str) -> subprocess.Popen:
    """
    Start a tshark process capturing on `interface`, filtered to `port`.
    Returns the Popen handle — caller is responsible for stopping it.
    Writes to: pcap_dir / f"{session_id}.pcap"

    tshark command:
      tshark -i {interface} -f "port {port}" -w {output_path} -q
    """
    ...

def stop_capture(proc: subprocess.Popen) -> None:
    """
    Gracefully terminate tshark. Wait up to 3 seconds, then kill if still running.
    """
    ...

def get_pcap_path(session_id: str, pcap_dir: Path) -> Path:
    """Returns the expected pcap file path for a session_id."""
    return pcap_dir / f"{session_id}.pcap"
```

---

### 4.2 `feature-extraction/pq_detector.py`

```python
"""
Detects Post-Quantum key shares in TLS ClientHello bytes.

TLS ClientHello binary layout reference:
  Byte 0:     Content Type (0x16 = Handshake)
  Bytes 1-2:  Legacy Version
  Bytes 3-4:  Record Length
  Byte 5:     Handshake Type (0x01 = ClientHello)
  Bytes 6-8:  Handshake Length (3 bytes, big-endian)
  Bytes 9-10: Client Version
  Bytes 11-42: Random (32 bytes)
  Byte 43:    Session ID Length
  Bytes 44+:  Session ID, then Cipher Suites, then Extensions...

Extensions relevant to us:
  - Type 0x000a (supported_groups): lists group IDs
  - Type 0x0033 (key_share): lists (group_id, key_data) pairs

PQ_GROUP_ID = 0x11EC  (X25519MLKEM768 — IANA-registered, current standard
as of 2025-2026, used by default in Caddy 2.10+ and current Chrome/Firefox)

Do NOT use 0x6399 — that is X25519Kyber768Draft00, a retired
pre-standardization draft codepoint. It is superseded and current browsers
do not send it. Checking for the wrong codepoint will silently fail to
detect real, current post-quantum traffic.
"""

def parse_clienthello(raw_bytes: bytes) -> dict:
    """
    Parse a raw TLS record containing a ClientHello.
    Returns a dict with:
      {
        "tls_version": int,
        "cipher_suites": list[int],
        "extensions": list[{"type": int, "data": bytes}],
        "supported_groups": list[int],
        "key_shares": list[{"group": int, "data_len": int}],
        "alpn": list[str],
      }
    Raises ValueError if bytes do not look like a ClientHello.
    """
    ...

def detect_pq_keyshare(parsed: dict) -> tuple[bool, int]:
    """
    Given output of parse_clienthello(), checks parsed["key_shares"] for
    an entry with group == 0x11EC.
    Returns (has_pq_keyshare: bool, pq_keyshare_data_len: int).
    pq_keyshare_data_len is -1 if has_pq_keyshare is False.
    Expect ~1216 bytes when present — confirm the exact value empirically
    against your own Phase 1 capture rather than hardcoding either this
    or any other number blindly.
    """
    ...

def extract_pq_features_from_pcap(pcap_path: str) -> dict:
    """
    Open a pcap file, find the first TLS ClientHello packet,
    parse it, and return pq features dict:
      {
        "has_pq_keyshare": int,         # 0 or 1
        "pq_keyshare_data_len": int,    # -1 if absent
        "tls_version": int,
        "cipher_suite_count": int,
        "cipher_suite_order_hash": int,
        "extension_count": int,
        "extension_order_hash": int,
        "supported_groups_hash": int,
        "alpn_hash": int,
      }
    Uses scapy to read the pcap.
    """
    ...
```

---

### 4.3 `feature-extraction/quic_parser.py`

```python
"""
Parses QUIC Initial packets from pcap to extract transport features.
QUIC runs over UDP. Initial packets use a fixed key derivation (HKDF from
Connection ID) per RFC 9001, so they can be decrypted with known algorithms.

For our purposes, we only need:
  - Was QUIC used at all? (used_http3)
  - QUIC version (from the Long Header version field)
  - Number of transport parameters (from the CRYPTO frame)
  - Connection ID length

We use aioquic's parser utilities for QUIC Initial decryption.
"""
from scapy.all import rdpcap

def extract_quic_features_from_pcap(pcap_path: str) -> dict:
    """
    Scan pcap for UDP packets on port 443.
    If a QUIC Initial packet is found, return:
      {
        "used_http3": 1,
        "quic_version": int,
        "quic_transport_param_count": int,
        "quic_conn_id_len": int,
      }
    If no QUIC packets found:
      {
        "used_http3": 0,
        "quic_version": -1,
        "quic_transport_param_count": -1,
        "quic_conn_id_len": -1,
      }
    """
    ...

def _is_quic_initial(udp_payload: bytes) -> bool:
    """
    Check if a UDP payload is a QUIC Long Header Initial packet.
    QUIC Long Header: first byte has bit 7=1, bit 6=1, bits 5-4 = 00 (Initial).
    """
    if not udp_payload:
        return False
    first_byte = udp_payload[0]
    if not (first_byte & 0x80 and first_byte & 0x40):
        return False
    return (first_byte & 0x30) == 0x00
```

---

### 4.4 `feature-extraction/timing_extractor.py`

```python
"""
Extracts timing-based behavioral features from a pcap file.
These features differentiate human browsing patterns from bot scripts.
Treat as a SUPPLEMENTARY signal only — do not let it dominate the model
or overshadow the PQ/QUIC signals that are the project's core contribution.
"""
from scapy.all import rdpcap
import numpy as np

def extract_timing_features(pcap_path: str) -> dict:
    """
    Returns:
      {
        "inter_request_timing_cv": float,   # Coefficient of variation of inter-packet gaps.
                                            # Humans: high CV (erratic); Bots: low CV (uniform)
        "record_layer_timing_p50": float,   # Median TLS record gap in ms
        "session_request_count": int,       # Total TCP SYN packets = number of connections
      }

    CV = std / mean. A value near 0 means uniform (bot-like). A value > 1
    means human-like. Clip CV at 5.0 to avoid outlier dominance.
    """
    ...
```

---

### 4.5 `detection-service/proxy.py`

```python
"""
Active TCP-intercept reverse proxy (raw passthrough — does not terminate TLS).

Architecture:
  Client → [proxy.py listens on PROXY_LISTEN_PORT=8443, TCP]
               │
               ▼
           Accept raw TCP connection
               │
               ▼
           Read first 4096 bytes (ClientHello is always plaintext,
           regardless of TLS version — no decryption needed to read it)
               │
               ▼
           Call feature_realtime.extract_features(raw_bytes)
               │
               ▼
           Call scorer.score(features) → (label, confidence)
               │
         ┌─────┴──────┐
         ▼            ▼
      ALLOW         BLOCK
      open TCP     send minimal HTTP/1.1 403
      connection   response over raw TCP,
      to Caddy,    close connection
      pipe the
      already-read
      buffer plus
      all further
      bytes through
      bidirectionally
         │
         ▼
      Log to DB (live_events table)
      Emit WebSocket event via api.py

Key design point: this proxy never terminates or decrypts TLS itself. It
reads the plaintext ClientHello off the raw socket, decides, and if
allowed, transparently relays bytes onward to Caddy, which performs the
actual TLS/QUIC handshake with the original client. This avoids needing
to reimplement TLS 1.3 or post-quantum negotiation in the proxy, and
mirrors how real TLS-passthrough proxies (e.g., HAProxy's SNI routing)
work in production.
"""
import asyncio
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from traffic_gen.config import (
    PROXY_LISTEN_HOST, PROXY_LISTEN_PORT,
    CADDY_FORWARD_HOST, CADDY_FORWARD_PORT,
    SCORE_THRESHOLD,
)

async def handle_connection(client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> None:
    """
    Called for each incoming TCP connection.
    1. Read up to 4096 bytes (the ClientHello), keep the buffer
    2. Extract features via feature_realtime.extract_features()
    3. Score via scorer.score()
    4. Allow: open a new TCP connection to Caddy, write the already-read
       buffer to it first, then pipe both directions bidirectionally
    5. Block: write a minimal HTTP/1.1 403 response, close the connection
    """
    ...

async def pipe_bidirectional(reader1, writer1, reader2, writer2) -> None:
    """
    Pipe data between two asyncio streams in both directions simultaneously.
    Closes both when either direction reaches EOF.
    """
    ...

async def main():
    server = await asyncio.start_server(
        handle_connection,
        PROXY_LISTEN_HOST,
        PROXY_LISTEN_PORT,
    )
    print(f"[proxy] Listening on {PROXY_LISTEN_HOST}:{PROXY_LISTEN_PORT}")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
```

---

### 4.6 `detection-service/api.py`

```python
"""
FastAPI backend for the dashboard.
Reads from SQLite (live_events table) and pushes events over WebSocket.
"""
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import asyncio
import json
import sqlite3
import time

app = FastAPI(title="Bot Detection API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── REST endpoints ──────────────────────────────────────────────────────────

@app.get("/stats")
def get_stats():
    """
    Returns aggregate statistics for dashboard cards.
    {
      "total_sessions": int,
      "blocked_count": int,
      "allowed_count": int,
      "block_rate": float,
      "avg_latency_ms": float,
      "pq_detected_count": int,
      "quic_detected_count": int,
    }
    """
    ...

@app.get("/live-feed")
def get_live_feed(limit: int = 100):
    """Returns last `limit` events from live_events table, newest first."""
    ...

@app.get("/model-comparison")
def get_model_comparison():
    """
    Returns Experiment A vs B vs C metrics for the accuracy comparison chart.
    Reads from model_runs table.
    """
    ...

# ── WebSocket ────────────────────────────────────────────────────────────────

connected_clients: list[WebSocket] = []

@app.websocket("/ws/feed")
async def websocket_feed(websocket: WebSocket):
    """
    Pushes new live_events to connected dashboard clients in real time.
    Polls DB every 500ms for new rows (simple, reliable for demo scale).
    """
    await websocket.accept()
    connected_clients.append(websocket)
    last_id = 0
    try:
        while True:
            new_events = _fetch_events_since(last_id)
            if new_events:
                last_id = new_events[-1]["id"]
                await websocket.send_text(json.dumps(new_events))
            await asyncio.sleep(0.5)
    except WebSocketDisconnect:
        connected_clients.remove(websocket)

def _fetch_events_since(last_id: int) -> list[dict]:
    """Fetch new live_events rows with id > last_id."""
    ...
```

---

## Section 5 — Data Flow Diagram

```
session_orchestrator.py
    │  generates session_id, starts/stops capture sidecar
    │  writes session_manifest.csv
    ▼
capture_sidecar.py
    │  one pcap per session → pcap_store/{session_id}.pcap
    ▼
build_dataset.py
    │  for each pcap in pcap_store/:
    │    1. pq_detector.extract_pq_features_from_pcap(pcap)
    │    2. quic_parser.extract_quic_features_from_pcap(pcap)
    │    3. timing_extractor.extract_timing_features(pcap)
    │    4. ja4_extractor.extract_ja4(pcap)
    │    5. ja4h_extractor.extract_ja4h(pcap)
    │    6. join with session_manifest.csv on session_id
    │    7. write FeatureVector to SQLite (features table)
    │  export all rows → dataset.parquet
    ▼
train_baseline.py / train_enhanced.py
    │  load dataset.parquet
    │  filter to EXPERIMENT_X_FEATURES
    │  stratified train/val/test split (seed=42)
    │  fit XGBoost, log to MLflow
    │  save model to model_registry/
    ▼
evaluate.py
    │  load all 3 models from model_registry/
    │  compute metrics on held-out test set
    │  output: results/delta_table.csv, results/confusion_*.png
    ▼
proxy.py (runtime)
    │  on each connection:
    │    raw_bytes → feature_realtime.extract_features()
    │    → scorer.score() → allow/block
    │    → write to live_events table
    │    → DB poll by api.py → WebSocket push → dashboard
```

---

## Section 6 — Build Order (Sequential, No Skipping)

```
STEP 1:  Scaffold all directories and empty files (Section 2)
STEP 2:  Write .gitignore                              (Section 8)
STEP 3:  Write requirements.txt                         (Section 9)
STEP 4:  Write target-site/Caddyfile                    (Section 3.1 — corrected)
STEP 5:  Write target-site/server.js                    (Section 3.2)
STEP 6:  Write target-site/package.json                 (Section 9.2)
STEP 7:  Write traffic-gen/config.py                    (Section 3.3)
STEP 8:  Write feature-extraction/feature_schema.py     (Section 3.4 — corrected)
STEP 9:  Write ml/config.py                             (Section 3.5)
STEP 10: Write db/schema.sql                             (Section 3.6)
STEP 11: Write db/init_db.py                             (Section 9.3)
STEP 12: Write capture/capture_sidecar.py                (implement Section 4.1)
STEP 13: Write feature-extraction/pq_detector.py         (implement Section 4.2 — corrected)
STEP 14: Write feature-extraction/quic_parser.py         (implement Section 4.3)
STEP 15: Write feature-extraction/timing_extractor.py    (implement Section 4.4)
STEP 16: Write feature-extraction/ja4_extractor.py       (JA4 per FoxIO spec)
STEP 17: Write feature-extraction/ja4h_extractor.py      (JA4H HTTP fingerprint)
STEP 18: Write feature-extraction/build_dataset.py       (orchestrates steps 13-17)
STEP 19: Write traffic-gen/human_traffic.py
STEP 20: Write traffic-gen/bot_tier1_naive.py
STEP 21: Write traffic-gen/bot_tier2_evasive.py
STEP 22: Write traffic-gen/bot_tier3_sophisticated.py
STEP 23: Write traffic-gen/session_orchestrator.py
STEP 24: Write ml/train_baseline.py
STEP 25: Write ml/train_enhanced.py
STEP 26: Write ml/evaluate.py
STEP 27: Write ml/feature_importance.py                  (SHAP plots)
STEP 28: Write detection-service/feature_realtime.py
STEP 29: Write detection-service/scorer.py
STEP 30: Write detection-service/proxy.py                (implement Section 4.5)
STEP 31: Write detection-service/api.py                  (implement Section 4.6)
STEP 32: Write dashboard/                                 (React + Vite + Recharts)
STEP 33: Write tests/
STEP 34: Write run_all.ps1                                (Section 9.1)
STEP 35: Write README.md
```

**After each step: run the file and fix any import errors before moving to the next step. Do not batch multiple steps without verifying the previous one works.**

---

## Section 7 — Smoke Test Scripts (Run at Key Gates)

### Gate 1 — PQ/QUIC confirmed in Caddy

```powershell
# Terminal 1: Start target site
cd target-site; node server.js

# Terminal 2: Start Caddy
caddy run --config target-site/Caddyfile

# Terminal 3: Visit https://localhost/ in Chrome first, then verify:
tshark -i "\Device\NPF_Loopback" -Y "tls.handshake.type == 1" -V -c 1 | Select-String "mlkem768|11ec|11EC"
# PASS: at least one match on mlkem768 or 11ec/11EC.
# If you instead see "kyber" or "6399" anywhere in the output, that is a
# FAILURE signal — the deprecated draft group is being offered/seen
# instead of the current standard, and something upstream still needs
# fixing (most likely the Caddyfile curves directive or Caddy's version).

tshark -i "\Device\NPF_Loopback" -Y "quic" -c 5
# Should print QUIC packets if Chrome used HTTP/3.
```

Also verify independently of the browser and Wireshark:
```powershell
openssl s_client -connect localhost:443 -groups X25519MLKEM768 -brief
# Expected: Negotiated TLS1.3 group: X25519MLKEM768
```

**Do not proceed past this gate until both checks pass.**

### Gate 2 — Feature extraction working

```powershell
# Generate one test session manually
python traffic-gen/human_traffic.py --sessions 1 --output test_session

# Run feature extraction on the resulting pcap
python feature-extraction/build_dataset.py --pcap capture/pcap_store/test_session.pcap

# Check output
python -c "import pandas as pd; df = pd.read_parquet('feature-extraction/dataset.parquet'); print(df.dtypes); print(df[['has_pq_keyshare','used_http3','session_request_count']].head())"
```

### Gate 3 — Live proxy working

```powershell
# Terminal 1: Caddy on port 9443 (proxy will forward to it)
# (Update Caddyfile to use localhost:9443 for proxy testing, or run a
# second Caddy instance on that port)

# Terminal 2: Start proxy
python detection-service/proxy.py

# Terminal 3: Start API
uvicorn detection-service.api:app --host 127.0.0.1 --port 8000 --reload

# Terminal 4: Test with curl
curl -k https://127.0.0.1:8443/
# Should either get the site (allow) or a 403 (block), logged in DB
```

---

## Section 8 — `.gitignore`

```gitignore
# Python
.venv/
__pycache__/
*.pyc
*.pyo
*.pyd
.pytest_cache/
*.egg-info/
dist/
build/

# ML artifacts (large binary files)
ml/model_registry/*.joblib
ml/model_registry/*.pkl
mlruns/
mlflow.db
*.parquet

# Captures (large, regeneratable)
capture/pcap_store/*.pcap
!capture/pcap_store/.gitkeep

# Database
db/bot_detection.db

# Certs
target-site/certs/
target-site/logs/

# Node
node_modules/
dashboard/dist/

# Logs
*.log

# OS
.DS_Store
Thumbs.db
```

---

## Section 9 — `requirements.txt`

```txt
# Traffic generation
playwright==1.45.0
requests==2.32.0
httpx==0.27.0

# Packet capture and parsing
scapy==2.5.0
aioquic==1.2.0

# Data pipeline
pandas==2.2.0
pyarrow==16.0.0
numpy==1.26.0

# ML
scikit-learn==1.5.0
xgboost==2.1.0
catboost==1.2.5
shap==0.45.0
joblib==1.4.0
mlflow==2.14.0

# Detection service backend
fastapi==0.111.0
uvicorn[standard]==0.30.0
websockets==12.0

# Utilities
ruff==0.5.0
pytest==8.2.0
python-dotenv==1.0.0
```

---

## Section 9.1 — `run_all.ps1`

```powershell
<#
One-command startup for the full stack: target site, Caddy, detection
proxy, API, and dashboard. Run from the project root.
#>

Write-Host "Starting QUIC/PQ-TLS Bot Detection stack..." -ForegroundColor Cyan

# Activate Python venv
& ".\.venv\Scripts\Activate.ps1"

# 1. Target site (Express)
Write-Host "Starting target site..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd target-site; node server.js"
Start-Sleep -Seconds 2

# 2. Caddy
Write-Host "Starting Caddy..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "caddy run --config target-site/Caddyfile"
Start-Sleep -Seconds 2

# 3. Detection proxy
Write-Host "Starting detection proxy..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd $PWD; .\.venv\Scripts\Activate.ps1; python detection-service/proxy.py"
Start-Sleep -Seconds 1

# 4. FastAPI backend
Write-Host "Starting API..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd $PWD; .\.venv\Scripts\Activate.ps1; uvicorn detection-service.api:app --host 127.0.0.1 --port 8000"
Start-Sleep -Seconds 1

# 5. Dashboard (Vite dev server)
Write-Host "Starting dashboard..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd dashboard; npm run dev"
Start-Sleep -Seconds 3

Write-Host "All services started. Opening dashboard..." -ForegroundColor Green
Start-Process "http://localhost:5173"
```

---

## Section 9.2 — `target-site/package.json`

```json
{
  "name": "quic-pqtls-target-site",
  "version": "1.0.0",
  "description": "Honeypot target site for QUIC/PQ-TLS bot detection research",
  "main": "server.js",
  "scripts": {
    "start": "node server.js"
  },
  "dependencies": {
    "express": "^4.19.2",
    "helmet": "^7.1.0",
    "morgan": "^1.10.0"
  }
}
```

---

## Section 9.3 — `db/init_db.py`

```python
"""
Initializes the SQLite database from schema.sql.
Run once before any capture or training begins. Safe to re-run —
uses CREATE TABLE IF NOT EXISTS throughout.
"""
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from traffic_gen.config import DB_PATH

SCHEMA_PATH = Path(__file__).parent / "schema.sql"

def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    schema_sql = SCHEMA_PATH.read_text()
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.executescript(schema_sql)
        conn.commit()
        print(f"[init_db] Database initialized at {DB_PATH}")
    finally:
        conn.close()

if __name__ == "__main__":
    init_db()
```

---

## Section 10 — Handoff Instructions

**Use this as your instruction to whichever agent (Antigravity, Gemini, etc.) is building this:**

> I need you to build a cybersecurity research project from scratch, following this exact system design document in full — it is self-contained and supersedes any earlier version you may have seen.
>
> **Your job:** Follow Section 1 (Installation) first, confirming Caddy is version 2.10.0 or later. Then execute Section 6's build order, Steps 1 through 35, in sequence, without skipping ahead. After each step, run the file and confirm it works before moving to the next.
>
> **Rules:**
> - Follow the exact function signatures in Section 4. Do not rename functions or change their signatures.
> - Follow the exact feature schema in Section 3.4. Do not add or remove fields without flagging it first.
> - The post-quantum group ID is `0x11EC`. Do not use `0x6399` anywhere in this codebase — it is deprecated and will break the core detection signal silently.
> - The Caddyfile must not include an explicit `curves` directive — Caddy's default already includes the correct post-quantum group, and hand-specifying curves without including it will disable PQ support entirely.
> - Use only the packages listed in requirements.txt. Do not add new packages without explaining why.
> - Do not proceed past Gate 1 (Section 7) until both the tshark check and the independent OpenSSL check confirm `X25519MLKEM768`/`0x11EC` is negotiating correctly.
> - Windows is the OS. Use PowerShell syntax for shell commands. Use `pathlib.Path` everywhere in Python.
>
> Start with Step 1: scaffold the directory structure from Section 2.
