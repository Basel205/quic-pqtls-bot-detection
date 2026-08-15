"""
Extracts timing-based behavioral features from a pcap file.
These features differentiate human browsing patterns from bot scripts.
Treat as a SUPPLEMENTARY signal only — do not let it dominate the model
or overshadow the PQ/QUIC signals that are the project's core contribution.
"""
import struct
import sys
from pathlib import Path
_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))
from _paths import setup_paths; setup_paths(_ROOT)

import numpy as np
from scapy.all import rdpcap, TCP


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
    default = {
        "inter_request_timing_cv": 0.0,
        "record_layer_timing_p50": 0.0,
        "session_request_count":   0,
    }

    try:
        packets = rdpcap(str(pcap_path))
    except Exception:
        return default

    if not packets:
        return default

    # Collect timestamps for:
    # 1. TCP SYN packets (new connection attempts = new requests)
    # 2. TLS Application Data packets (record layer timing)
    syn_times = []
    tls_times = []

    for pkt in packets:
        if not pkt.haslayer(TCP):
            continue

        tcp = pkt[TCP]
        ts  = float(pkt.time)

        # SYN without ACK = new connection
        if tcp.flags == 0x02:
            syn_times.append(ts)

        # TLS application data: payload starts with 0x17
        payload = bytes(getattr(tcp, "payload", b"") or b"")
        if payload and payload[0] == 0x17 and len(payload) >= 5:
            tls_times.append(ts)

    # ── session_request_count ──────────────────────────────────────────────────
    session_request_count = len(syn_times)

    # ── inter_request_timing_cv ────────────────────────────────────────────────
    inter_request_timing_cv = 0.0
    if len(syn_times) >= 2:
        gaps = np.diff(sorted(syn_times)) * 1000.0  # ms
        mean = np.mean(gaps)
        if mean > 0:
            cv = np.std(gaps) / mean
            inter_request_timing_cv = float(np.clip(cv, 0.0, 5.0))

    # ── record_layer_timing_p50 ────────────────────────────────────────────────
    record_layer_timing_p50 = 0.0
    if len(tls_times) >= 2:
        gaps = np.diff(sorted(tls_times)) * 1000.0  # ms
        record_layer_timing_p50 = float(np.percentile(gaps, 50))

    return {
        "inter_request_timing_cv": inter_request_timing_cv,
        "record_layer_timing_p50": record_layer_timing_p50,
        "session_request_count":   session_request_count,
    }
