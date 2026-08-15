"""
Canonical feature schema for the bot detection classifier.
This is the SINGLE SOURCE OF TRUTH for feature names, types, and nullability.
Both the training pipeline and the real-time proxy use this schema.
Any change here must be reflected in both.
"""
from dataclasses import dataclass, field
from typing import Optional, List

# ── PQ Key Share ─────────────────────────────────────────────────────────────
# X25519MLKEM768 group ID as registered by IANA (hex 0x11EC = decimal 4588)
PQ_GROUP_ID = 0x11EC

# ── Feature Names ────────────────────────────────────────────────────────────
# Split into sets for experiment config
CLASSICAL_FEATURES = [
    "ja4_fingerprint_hash",    # int (hashed for ML)
    "tls_version",             # int (771=TLS1.3, 772=draft, etc.)
    "cipher_suite_count",      # int
    "cipher_suite_order_hash", # int (hashed)
    "extension_count",         # int
    "extension_order_hash",    # int (hashed)
    "supported_groups_hash",   # int (hashed multi-hot)
    "alpn_hash",               # int (hashed ALPN list)
]

NEW_PROTOCOL_FEATURES = [
    "has_pq_keyshare",         # bool (0/1)
    "pq_keyshare_data_len",    # int (nullable → -1 if absent)
    "used_http3",              # bool (0/1)
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
EXPERIMENT_C_FEATURES = CLASSICAL_FEATURES + NEW_PROTOCOL_FEATURES    # Ablation

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
