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
HUMAN_DELAY_MEAN   = 2.5   # Mean delay between page actions (humans)
HUMAN_DELAY_STD    = 1.2   # Std dev — randomness is the key difference from bots
HUMAN_SESSION_REQS = (5, 15)  # (min, max) requests per human session

BOT_DELAY_MEAN     = 0.05  # Bots are fast
BOT_DELAY_STD      = 0.01

# ── Session targets ──────────────────────────────────────────────────────────
SESSIONS_HUMAN  = 500
SESSIONS_TIER1  = 400
SESSIONS_TIER2  = 400
SESSIONS_TIER3  = 300
SESSIONS_TIER4  = 200  # Evasion bots — run separately after model is trained

# Fraction of Tier-4 sessions that run the "degraded" backend profile
# (--disable-quic) instead of "full" (genuine PQ+QUIC, matches human exactly).
# Models a distributed bot operation that can't guarantee every worker/exit-node
# in a claimed-identity group proxies QUIC's UDP traffic — see bot_tier4_adaptive.py.
TIER4_DEGRADED_PROFILE_PROB = 0.3

# ── Capture ──────────────────────────────────────────────────────────────────
# Confirmed via `tshark -D` + a live 3s test capture on 2026-08-16 — this
# interface captures loopback traffic on this machine. Re-verify with
# `tshark -D` if this project moves to a different machine.
TSHARK_INTERFACE = r"\Device\NPF_Loopback"
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
