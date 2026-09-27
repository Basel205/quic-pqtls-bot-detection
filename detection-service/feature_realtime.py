"""
Real-time ClientHello feature extraction for the Phase 6 detection proxy.

Reuses feature-extraction/pq_detector.py's parse_clienthello() and
detect_pq_keyshare() UNCHANGED — that function already operates on raw bytes
with no pcap dependency (confirmed by reading it directly), so the exact
same, already-tested parsing logic applies whether the bytes came from a
pcap file or a live socket. This module is the "get bytes off a live
connection and call it" glue, not a reimplementation.

Honest scoping note: a single ClientHello peek on a TCP connection gives you
the CLASSICAL_FEATURES and NEW_PROTOCOL_FEATURES' PQ half (has_pq_keyshare,
pq_keyshare_data_len) — it does NOT give you used_http3/quic_* (those require
separately watching the UDP/443 port for a QUIC Initial packet, a genuinely
different code path — see quic_parser.py) or BEHAVIORAL_FEATURES (those need
multiple requests over the session, not the first ClientHello alone). The
scorer below fills those with the "absent"/neutral defaults the training
data uses for missing values, and scores on partial information — this is a
real, disclosed limitation of the TCP-passthrough architecture, not a bug:
a connection-establishment-time decision can only ever use
connection-establishment-time information.
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
from _paths import setup_paths; setup_paths(_ROOT)
sys.path.insert(0, str(_ROOT / "feature-extraction"))

from pq_detector import parse_clienthello, detect_pq_keyshare, multi_hot_supported_groups, multi_hot_alpn
from ja4_extractor import _compute_ja4


async def read_clienthello(reader, timeout: float = 2.0) -> bytes:
    """Reads exactly one TLS record (the ClientHello) off an asyncio
    StreamReader without consuming more than that record — the proxy needs
    to relay these same bytes onward afterward, so this must not swallow
    anything beyond the record it parses."""
    import asyncio
    header = await asyncio.wait_for(reader.readexactly(5), timeout=timeout)
    if header[0] != 0x16:
        raise ValueError(f"not a TLS handshake record (content_type={header[0]:#x})")
    record_length = int.from_bytes(header[3:5], "big")
    body = await asyncio.wait_for(reader.readexactly(record_length), timeout=timeout)
    return header + body


def extract_realtime_features(raw_clienthello: bytes) -> dict:
    """Returns a feature dict with the fields extractable from a single
    ClientHello, and explicit -1/0 defaults (matching dataset.parquet's own
    convention for nullable/absent fields) for what a TCP-only peek cannot
    know yet."""
    parsed = parse_clienthello(raw_clienthello)
    has_pq, pq_len = detect_pq_keyshare(parsed)
    sg = multi_hot_supported_groups(parsed["supported_groups"])
    alpn = multi_hot_alpn(parsed["alpn"])
    ja4 = _compute_ja4(parsed)

    features = {
        "ja4_fingerprint_hash":      hash(ja4) & 0xFFFFFFFF,
        "tls_version":               parsed["tls_version"],
        "cipher_suite_count":        len(parsed["cipher_suites"]),
        "cipher_suite_order_hash":   hash(tuple(parsed["cipher_suites"])) & 0xFFFFFFFF,
        "extension_count":           len(parsed["extensions"]),
        "extension_order_hash":      hash(tuple(e["type"] for e in parsed["extensions"])) & 0xFFFFFFFF,
        "has_pq_keyshare":           int(has_pq),
        "pq_keyshare_data_len":      pq_len,
        # Not knowable from a single TCP ClientHello — see module docstring.
        "used_http3":                0,
        "quic_version":              -1,
        "quic_transport_param_count": -1,
        "quic_conn_id_len":          -1,
        "inter_request_timing_cv":   0.0,
        "record_layer_timing_p50":   0.0,
        "session_request_count":     1,
        "ja4h_fingerprint_hash":     0,
        **sg,
        **alpn,
    }
    return features
