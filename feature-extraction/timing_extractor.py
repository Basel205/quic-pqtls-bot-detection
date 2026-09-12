"""
Extracts timing-based behavioral features.
These features differentiate human browsing patterns from bot scripts.
Treat as a SUPPLEMENTARY signal only — do not let it dominate the model
or overshadow the PQ/QUIC signals that are the project's core contribution.
"""
import json
import sys
from pathlib import Path
_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))
from _paths import setup_paths; setup_paths(_ROOT)

import numpy as np
from scapy.all import rdpcap, TCP


def extract_timing_features(pcap_path: str, session_id: str, access_log_path: str) -> dict:
    """
    Returns:
      {
        "inter_request_timing_cv": float,   # Coefficient of variation of inter-HTTP-request gaps.
                                            # Humans: high CV (erratic); Bots: low CV (uniform)
        "record_layer_timing_p50": float,   # Median TLS record gap in ms (from pcap)
        "session_request_count": int,       # Total HTTP requests in the session (from access.log)
      }

    inter_request_timing_cv and session_request_count come from Caddy's access
    log (matched via the X-Session-ID header, same approach as ja4h_extractor)
    rather than from TCP SYNs: sessions use HTTP keep-alive, so a session with
    many requests still opens only 0-1 new TCP connections, and QUIC/HTTP3
    sessions have no TCP SYN at all — a SYN-based count would misread both.

    CV = std / mean. A value near 0 means uniform (bot-like). A value > 1
    means human-like. Clip CV at 5.0 to avoid outlier dominance.
    """
    default = {
        "inter_request_timing_cv": 0.0,
        "record_layer_timing_p50": 0.0,
        "session_request_count":   0,
    }

    # ── record_layer_timing_p50 (pcap-based) ────────────────────────────────────
    record_layer_timing_p50 = 0.0
    try:
        packets = rdpcap(str(pcap_path))
    except Exception:
        packets = []

    tls_times = []
    for pkt in packets:
        if not pkt.haslayer(TCP):
            continue
        tcp = pkt[TCP]
        # TLS application data: payload starts with 0x17
        payload = bytes(getattr(tcp, "payload", b"") or b"")
        if payload and payload[0] == 0x17 and len(payload) >= 5:
            tls_times.append(float(pkt.time))

    if len(tls_times) >= 2:
        gaps = np.diff(sorted(tls_times)) * 1000.0  # ms
        record_layer_timing_p50 = float(np.percentile(gaps, 50))

    # ── session_request_count / inter_request_timing_cv (access.log-based) ─────
    request_times = _request_timestamps_for_session(session_id, access_log_path)
    session_request_count = len(request_times)

    inter_request_timing_cv = 0.0
    if len(request_times) >= 2:
        gaps = np.diff(sorted(request_times)) * 1000.0  # ms
        mean = np.mean(gaps)
        if mean > 0:
            cv = np.std(gaps) / mean
            inter_request_timing_cv = float(np.clip(cv, 0.0, 5.0))

    return {
        "inter_request_timing_cv": inter_request_timing_cv,
        "record_layer_timing_p50": record_layer_timing_p50,
        "session_request_count":   session_request_count,
    }


def _request_timestamps_for_session(session_id: str, access_log_path: str) -> list[float]:
    """Scan Caddy's JSON access log for all requests carrying this session's
    X-Session-ID header, returning their `ts` (Unix timestamp) values."""
    log_path = Path(access_log_path)
    if not log_path.exists():
        return []

    timestamps: list[float] = []
    try:
        with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                headers = entry.get("request", {}).get("headers", {})
                sid_values = headers.get("X-Session-Id", headers.get("X-Session-ID", []))
                if isinstance(sid_values, list) and session_id not in sid_values:
                    continue
                if isinstance(sid_values, str) and sid_values != session_id:
                    continue
                if not sid_values:
                    continue

                ts = entry.get("ts")
                if ts is not None:
                    timestamps.append(float(ts))
    except OSError:
        return []

    return timestamps
