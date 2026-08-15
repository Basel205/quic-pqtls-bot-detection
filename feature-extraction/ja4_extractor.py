"""
JA4 TLS fingerprint extractor.
Implements the FoxIO JA4 specification: https://github.com/FoxIO-LLC/ja4

JA4 format: {tls_version}{sni_flag}{num_ciphers}{num_extensions}{alpn_first}{_}{sorted_ciphers}{_}{sorted_extensions}
Hashed to a 12-character hex prefix per the spec.

We derive JA4 from raw pcap TLS ClientHello bytes via pq_detector.parse_clienthello().
"""
import hashlib
import struct
import sys
from pathlib import Path
_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))
from _paths import setup_paths; setup_paths(_ROOT)

from pq_detector import parse_clienthello, _extract_raw_payload
from scapy.all import rdpcap


# TLS version codes → JA4 version strings
_TLS_VERSION_MAP = {
    0x0301: "10",
    0x0302: "11",
    0x0303: "12",
    0x0304: "13",
}

# Extension types to exclude from JA4 (per FoxIO spec)
_JA4_EXCLUDED_EXTENSIONS = {0x0000, 0x0010}  # SNI, ALPN

# GREASE values to exclude (RFC 8701)
_GREASE = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A,
    0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
    0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
}


def extract_ja4(pcap_path: str) -> dict:
    """
    Open a pcap, find the first TLS ClientHello, compute JA4.
    Returns:
      {
        "ja4_fingerprint": str,        # full JA4 string
        "ja4_fingerprint_hash": int,   # integer hash for ML
      }
    """
    default = {"ja4_fingerprint": "", "ja4_fingerprint_hash": 0}

    try:
        packets = rdpcap(str(pcap_path))
    except Exception:
        return default

    for pkt in packets:
        raw = _extract_raw_payload(pkt)
        if raw is None:
            continue
        if len(raw) >= 6 and raw[0] == 0x16 and raw[5] == 0x01:
            try:
                parsed = parse_clienthello(raw)
            except ValueError:
                continue

            ja4 = _compute_ja4(parsed)
            ja4_hash = int(hashlib.sha256(ja4.encode()).hexdigest(), 16) % (2**31)
            return {"ja4_fingerprint": ja4, "ja4_fingerprint_hash": ja4_hash}

    return default


def _compute_ja4(parsed: dict) -> str:
    """
    Compute the JA4 string from a parsed ClientHello dict.
    Format: {ver}{sni}{num_cs}{num_ext}{alpn_first}_{sorted_cs_hash}_{sorted_ext_hash}
    """
    # TLS version — use highest advertised in supported_versions extension (type 0x002b)
    # Fall back to the legacy client_version field
    tls_ver_raw = parsed["tls_version"]

    # Check supported_versions extension for TLS 1.3
    for ext in parsed["extensions"]:
        if ext["type"] == 0x002B:
            data = ext["data"]
            # First byte is the list length
            if len(data) >= 3:
                sv_len = data[0]
                for i in range(0, sv_len, 2):
                    if 1 + i + 2 <= len(data):
                        sv = struct.unpack_from(">H", data, 1 + i)[0]
                        if sv == 0x0304:  # TLS 1.3
                            tls_ver_raw = 0x0304
                            break

    tls_ver_str = _TLS_VERSION_MAP.get(tls_ver_raw, "00")

    # SNI flag
    has_sni = any(e["type"] == 0x0000 for e in parsed["extensions"])
    sni_flag = "d" if has_sni else "i"

    # Cipher suites — exclude GREASE
    ciphers = [c for c in parsed["cipher_suites"] if c not in _GREASE]
    num_cs  = len(ciphers)

    # Extensions — exclude GREASE
    exts    = [e["type"] for e in parsed["extensions"] if e["type"] not in _GREASE]
    num_ext = len(exts)

    # ALPN first value (2-char truncated)
    alpn_first = parsed["alpn"][0][:2] if parsed["alpn"] else "00"

    # Sorted cipher suites (hex, comma-separated), then hashed
    sorted_cs_str  = ",".join(f"{c:04x}" for c in sorted(ciphers))
    sorted_cs_hash = hashlib.sha256(sorted_cs_str.encode()).hexdigest()[:12]

    # Sorted extensions (excluding SNI + ALPN), hashed
    sorted_ext     = sorted(e for e in exts if e not in _JA4_EXCLUDED_EXTENSIONS)
    sorted_ext_str = ",".join(f"{e:04x}" for e in sorted_ext)
    sorted_ext_hash = hashlib.sha256(sorted_ext_str.encode()).hexdigest()[:12]

    ja4 = f"t{tls_ver_str}{sni_flag}{num_cs:02d}{num_ext:02d}{alpn_first}_{sorted_cs_hash}_{sorted_ext_hash}"
    return ja4
