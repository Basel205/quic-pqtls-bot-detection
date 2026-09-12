"""
Loads external, independently-collected TLS fingerprint data and normalizes it
into this project's own multi-hot feature vocabulary (see feature_schema.py's
SUPPORTED_GROUPS_VOCAB / ALPN_VOCAB), so it can sit alongside our own
lab-generated dataset.parquet when building the Step 5 expected-combination
table. See external-data/README.md for what this data is and why it's here.
"""
import csv
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))
from _paths import setup_paths; setup_paths(_ROOT)

from feature_schema import SUPPORTED_GROUPS_VOCAB, ALPN_VOCAB

EXTERNAL_CSV = Path(__file__).parent / "external-data" / "llm_agent_study_tls_fingerprints.csv"

# OpenSSL's SSL_curves variable uses its own aliases for some groups —
# map them onto the same names SUPPORTED_GROUPS_VOCAB uses.
_CURVE_ALIASES = {
    "X25519":     "x25519",
    "prime256v1": "secp256r1",  # OpenSSL alias for secp256r1
    "secp384r1":  "secp384r1",
    "secp521r1":  "secp521r1",
    "0x11ec":     "x25519mlkem768",
}

_GREASE_HEX = {
    "0x0a0a", "0x1a1a", "0x2a2a", "0x3a3a", "0x4a4a", "0x5a5a",
    "0x6a6a", "0x7a7a", "0x8a8a", "0x9a9a", "0xaaaa", "0xbaba",
    "0xcaca", "0xdada", "0xeaea", "0xfafa",
}

_ALPN_FIELD = {p: f"alpn_{p.replace('/', '').replace('.', '')}" for p in ALPN_VOCAB}


def _multi_hot_curves(curves_field: str) -> dict:
    out = {f"sg_{name}": 0 for name in SUPPORTED_GROUPS_VOCAB.values()}
    out["sg_other"] = 0
    for raw in curves_field.split(":"):
        raw = raw.strip()
        if not raw or raw.lower() in _GREASE_HEX:
            continue
        name = _CURVE_ALIASES.get(raw)
        if name is not None:
            out[f"sg_{name}"] = 1
        else:
            out["sg_other"] = 1
    return out


def _multi_hot_alpn(alpn_field: str) -> dict:
    """
    NOTE: this is the *negotiated* protocol (single value), not the full
    *offered* list our own pipeline parses from the raw ClientHello — see
    external-data/README.md's granularity-mismatch note. We only assert
    "this protocol was present", never "this was the complete offered set".
    """
    out = {field: 0 for field in _ALPN_FIELD.values()}
    out["alpn_other"] = 0
    alpn_field = alpn_field.strip()
    field = _ALPN_FIELD.get(alpn_field)
    if field is not None:
        out[field] = 1
    elif alpn_field and alpn_field != "-":
        out["alpn_other"] = 1
    return out


def load_external_reference() -> list[dict]:
    """
    Returns a list of normalized rows:
      {
        "source": "external_llm_agent_study",
        "tool_label": str,             # e.g. "Human", "Selenium", "ChatGPT Agent"
        "tls_version": int,            # 771 for TLS 1.3, matching our own convention
        "has_pq_keyshare": int,
        "used_http3": int,             # inferred: alpn negotiated == "h3"
        "sg_x25519": int, ... "sg_other": int,
        "alpn_h2": int, ... "alpn_other": int,
      }
    Skips rows with no usable TLS data (blank ssl_protocol_pcap — connection
    never reached the TLS layer, e.g. blocked/timed-out probes).
    """
    if not EXTERNAL_CSV.exists():
        return []

    rows_out = []
    with open(EXTERNAL_CSV, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            proto = (row.get("ssl_protocol_pcap") or "").strip()
            if not proto:
                continue

            curves = row.get("SSL_curves_pcap") or ""
            alpn = row.get("SSL_alpn_protocol_pcap") or ""
            sg = _multi_hot_curves(curves)
            alpn_hot = _multi_hot_alpn(alpn)

            rows_out.append({
                "source": "external_llm_agent_study",
                "tool_label": row.get("Web Agent", ""),
                "tls_version": 771 if "1.3" in proto else 0,
                "has_pq_keyshare": sg["sg_x25519mlkem768"],
                "used_http3": 1 if alpn.strip() == "h3" else 0,
                **sg,
                **alpn_hot,
            })

    return rows_out


if __name__ == "__main__":
    rows = load_external_reference()
    print(f"Loaded {len(rows)} external reference rows")
    from collections import Counter
    print("By tool_label:", Counter(r["tool_label"] for r in rows))
