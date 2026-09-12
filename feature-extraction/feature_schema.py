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

# ── Multi-hot vocabularies ───────────────────────────────────────────────────
# Step 3 decision (2026-08-18): supported_groups/alpn are multi-hot, not a
# single hash — the spatial-inconsistency scoring in Step 5 needs to know
# *which* attribute combination a session presented, not just an opaque digest
# of it. Each known value gets its own bit; anything outside the vocabulary
# (or an unrecognized ALPN string) sets the "_other" catch-all bit instead of
# being silently dropped, so unusual combinations still leave a signal.
# GREASE values (RFC 8701) are excluded from supported_groups matching —
# browsers routinely include one at a random codepoint, and counting that
# towards "other" would make the bit fire on nearly every real session.
SUPPORTED_GROUPS_VOCAB = {
    0x001D: "x25519",
    0x0017: "secp256r1",
    0x0018: "secp384r1",
    0x0019: "secp521r1",
    PQ_GROUP_ID: "x25519mlkem768",
}
ALPN_VOCAB = ["h2", "http/1.1", "h3"]

SUPPORTED_GROUPS_FIELDS = [f"sg_{name}" for name in SUPPORTED_GROUPS_VOCAB.values()] + ["sg_other"]
ALPN_FIELDS = [f"alpn_{name.replace('/', '').replace('.', '')}" for name in ALPN_VOCAB] + ["alpn_other"]

# ── Feature Names ────────────────────────────────────────────────────────────
# Split into sets for experiment config
CLASSICAL_FEATURES = [
    "ja4_fingerprint_hash",    # int (hashed for ML)
    "tls_version",             # int (771=TLS1.3, 772=draft, etc.)
    "cipher_suite_count",      # int
    "cipher_suite_order_hash", # int (hashed)
    "extension_count",         # int
    "extension_order_hash",    # int (hashed)
] + SUPPORTED_GROUPS_FIELDS + ALPN_FIELDS  # each a bool (0/1) — see vocab above

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

# D1/D2 (consistency-layer/) — engineered scores joined in at load time, not
# present in dataset.parquet itself. See consistency-layer/spatial_score.py
# and temporal_score.py.
SPATIAL_SCORE_COL  = "spatial_inconsistency_score"
TEMPORAL_SCORE_COL = "temporal_inconsistency_score"
EXPERIMENT_D1_FEATURES = ALL_FEATURES + [SPATIAL_SCORE_COL]                       # B + spatial
EXPERIMENT_D2_FEATURES = ALL_FEATURES + [SPATIAL_SCORE_COL, TEMPORAL_SCORE_COL]   # D1 + temporal

# Ablation Study arms (CLAUDE.md's Ablation Study section) — Spatial-consistency-only
# and Full-consistency-only. Deliberately CLASSICAL_FEATURES, not ALL_FEATURES: excludes
# NEW_PROTOCOL_FEATURES (has_pq_keyshare, used_http3, quic_*) and BEHAVIORAL_FEATURES
# (timing) so the model can't fall back on those raw presence/timing signals — added
# after the Tier-4 evasion test found D1/D2 give the consistency scores 0.0 feature
# importance on ALL_FEATURES, because the scores are a deterministic/redundant function
# of has_pq_keyshare/used_http3 on the lab training distribution. These arms test
# whether the scores carry independent signal once that shortcut isn't available. See
# CLAUDE.md.
EXPERIMENT_SPATIAL_ONLY_FEATURES = CLASSICAL_FEATURES + [SPATIAL_SCORE_COL]
EXPERIMENT_FULL_CONSISTENCY_FEATURES = CLASSICAL_FEATURES + [SPATIAL_SCORE_COL, TEMPORAL_SCORE_COL]

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

    # supported_groups / alpn — multi-hot (see SUPPORTED_GROUPS_VOCAB / ALPN_VOCAB above)
    sg_x25519: int                  = 0
    sg_secp256r1: int               = 0
    sg_secp384r1: int               = 0
    sg_secp521r1: int               = 0
    sg_x25519mlkem768: int          = 0
    sg_other: int                   = 0
    alpn_h2: int                    = 0
    alpn_http11: int                = 0
    alpn_h3: int                    = 0
    alpn_other: int                 = 0

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
