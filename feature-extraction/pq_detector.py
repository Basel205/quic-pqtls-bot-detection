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

import hashlib
import struct
import sys
from pathlib import Path
_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))
from _paths import setup_paths; setup_paths(_ROOT)

from scapy.all import rdpcap, Raw

from feature_schema import PQ_GROUP_ID, SUPPORTED_GROUPS_VOCAB, ALPN_VOCAB


# ── Extension type constants ──────────────────────────────────────────────────
EXT_SUPPORTED_GROUPS = 0x000A
EXT_KEY_SHARE        = 0x0033
EXT_ALPN             = 0x0010

# GREASE values (RFC 8701) — excluded from supported_groups matching since
# browsers routinely include one at a random codepoint; counting it toward
# "other" would fire on nearly every real session.
_GREASE = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A,
    0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
    0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
}


def multi_hot_supported_groups(groups: list[int]) -> dict:
    """Multi-hot encode a ClientHello's supported_groups list per SUPPORTED_GROUPS_VOCAB."""
    out = {f"sg_{name}": 0 for name in SUPPORTED_GROUPS_VOCAB.values()}
    out["sg_other"] = 0
    for g in groups:
        if g in _GREASE:
            continue
        name = SUPPORTED_GROUPS_VOCAB.get(g)
        if name is not None:
            out[f"sg_{name}"] = 1
        else:
            out["sg_other"] = 1
    return out


def multi_hot_alpn(protocols: list[str]) -> dict:
    """Multi-hot encode a ClientHello's ALPN protocol list per ALPN_VOCAB."""
    out = {f"alpn_{p.replace('/', '').replace('.', '')}": 0 for p in ALPN_VOCAB}
    out["alpn_other"] = 0
    for p in protocols:
        field = f"alpn_{p.replace('/', '').replace('.', '')}"
        if field in out:
            out[field] = 1
        else:
            out["alpn_other"] = 1
    return out


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
    if len(raw_bytes) < 5:
        raise ValueError("Too short to be a TLS record")

    # TLS record header
    content_type = raw_bytes[0]
    if content_type != 0x16:
        raise ValueError(f"Not a TLS Handshake record: content_type={content_type:#x}")

    record_length = struct.unpack_from(">H", raw_bytes, 3)[0]
    if len(raw_bytes) < 5 + record_length:
        raise ValueError("Truncated TLS record")

    # Handshake header starts at byte 5
    pos = 5
    handshake_type = raw_bytes[pos]
    if handshake_type != 0x01:
        raise ValueError(f"Not a ClientHello: handshake_type={handshake_type:#x}")

    # Handshake length is 3 bytes big-endian
    hs_len = struct.unpack_from(">I", b"\x00" + raw_bytes[pos + 1: pos + 4])[0]
    pos += 4

    end = pos + hs_len

    # Client Version (2 bytes)
    client_version = struct.unpack_from(">H", raw_bytes, pos)[0]
    pos += 2

    # Random (32 bytes)
    pos += 32

    # Session ID
    session_id_len = raw_bytes[pos]
    pos += 1 + session_id_len

    # Cipher Suites
    cs_len = struct.unpack_from(">H", raw_bytes, pos)[0]
    pos += 2
    cipher_suites = []
    for i in range(0, cs_len, 2):
        cs = struct.unpack_from(">H", raw_bytes, pos + i)[0]
        cipher_suites.append(cs)
    pos += cs_len

    # Compression Methods
    cm_len = raw_bytes[pos]
    pos += 1 + cm_len

    # Extensions
    extensions = []
    supported_groups = []
    key_shares = []
    alpn_protocols = []

    if pos + 2 <= end:
        ext_total_len = struct.unpack_from(">H", raw_bytes, pos)[0]
        pos += 2
        ext_end = pos + ext_total_len

        while pos + 4 <= ext_end:
            ext_type = struct.unpack_from(">H", raw_bytes, pos)[0]
            ext_len  = struct.unpack_from(">H", raw_bytes, pos + 2)[0]
            ext_data = raw_bytes[pos + 4: pos + 4 + ext_len]
            extensions.append({"type": ext_type, "data": ext_data})
            pos += 4 + ext_len

            # Parse supported_groups (0x000a)
            if ext_type == EXT_SUPPORTED_GROUPS and len(ext_data) >= 2:
                groups_len = struct.unpack_from(">H", ext_data, 0)[0]
                for i in range(0, groups_len, 2):
                    if 2 + i + 2 <= len(ext_data):
                        g = struct.unpack_from(">H", ext_data, 2 + i)[0]
                        supported_groups.append(g)

            # Parse key_share (0x0033)
            elif ext_type == EXT_KEY_SHARE and len(ext_data) >= 2:
                ks_pos = 0
                # In ClientHello, key_share starts with a 2-byte length prefix
                if len(ext_data) >= 2:
                    ks_list_len = struct.unpack_from(">H", ext_data, ks_pos)[0]
                    ks_pos += 2
                    ks_end = ks_pos + ks_list_len
                    while ks_pos + 4 <= ks_end and ks_pos + 4 <= len(ext_data):
                        ks_group   = struct.unpack_from(">H", ext_data, ks_pos)[0]
                        ks_data_len = struct.unpack_from(">H", ext_data, ks_pos + 2)[0]
                        key_shares.append({"group": ks_group, "data_len": ks_data_len})
                        ks_pos += 4 + ks_data_len

            # Parse ALPN (0x0010)
            elif ext_type == EXT_ALPN and len(ext_data) >= 2:
                alpn_pos = 2  # skip outer length
                while alpn_pos < len(ext_data):
                    proto_len = ext_data[alpn_pos]
                    alpn_pos += 1
                    proto = ext_data[alpn_pos: alpn_pos + proto_len].decode("ascii", errors="ignore")
                    alpn_protocols.append(proto)
                    alpn_pos += proto_len

    return {
        "tls_version":      client_version,
        "cipher_suites":    cipher_suites,
        "extensions":       extensions,
        "supported_groups": supported_groups,
        "key_shares":       key_shares,
        "alpn":             alpn_protocols,
    }


def detect_pq_keyshare(parsed: dict) -> tuple[bool, int]:
    """
    Given output of parse_clienthello(), checks parsed["key_shares"] for
    an entry with group == 0x11EC.
    Returns (has_pq_keyshare: bool, pq_keyshare_data_len: int).
    pq_keyshare_data_len is -1 if has_pq_keyshare is False.
    Expect ~1216 bytes when present — confirm the exact value empirically
    against your own Phase 1 capture rather than hardcoding this value.
    """
    for ks in parsed.get("key_shares", []):
        if ks["group"] == PQ_GROUP_ID:
            return True, ks["data_len"]
    return False, -1


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
        "sg_x25519": int, "sg_secp256r1": int, "sg_secp384r1": int,
        "sg_secp521r1": int, "sg_x25519mlkem768": int, "sg_other": int,
        "alpn_h2": int, "alpn_http11": int, "alpn_h3": int, "alpn_other": int,
        "tcp_alpn": list[str],   # raw ALPN list as offered in this (TCP-layer) ClientHello
      }
    The alpn_* multi-hot fields above reflect only this TCP-layer ClientHello;
    a session may separately negotiate QUIC with its own ALPN (see
    quic_parser.py's "quic_alpn") — build_dataset.py merges both before
    computing the FeatureVector's final alpn_* fields.
    Uses scapy to read the pcap.
    """
    default = {
        "has_pq_keyshare":       0,
        "pq_keyshare_data_len":  -1,
        "tls_version":           0,
        "cipher_suite_count":    0,
        "cipher_suite_order_hash": 0,
        "extension_count":       0,
        "extension_order_hash":  0,
        **multi_hot_supported_groups([]),
        **multi_hot_alpn([]),
        "tcp_alpn":              [],
    }

    try:
        packets = rdpcap(str(pcap_path))
    except Exception:
        return default

    for pkt in packets:
        raw = _extract_raw_payload(pkt)
        if raw is None:
            continue
        # Look for TLS handshake (content_type=0x16, handshake_type=0x01)
        if len(raw) >= 6 and raw[0] == 0x16 and raw[5] == 0x01:
            try:
                parsed = parse_clienthello(raw)
            except ValueError:
                continue

            has_pq, pq_len = detect_pq_keyshare(parsed)

            cipher_str   = ",".join(str(c) for c in parsed["cipher_suites"])
            ext_str      = ",".join(str(e["type"]) for e in parsed["extensions"])

            def _hash(s: str) -> int:
                return int(hashlib.md5(s.encode()).hexdigest(), 16) % (2**31)

            return {
                "has_pq_keyshare":       int(has_pq),
                "pq_keyshare_data_len":  pq_len,
                "tls_version":           parsed["tls_version"],
                "cipher_suite_count":    len(parsed["cipher_suites"]),
                "cipher_suite_order_hash": _hash(cipher_str),
                "extension_count":       len(parsed["extensions"]),
                "extension_order_hash":  _hash(ext_str),
                **multi_hot_supported_groups(parsed["supported_groups"]),
                **multi_hot_alpn(parsed["alpn"]),
                "tcp_alpn": parsed["alpn"],
            }

    return default


def _extract_raw_payload(pkt) -> bytes | None:
    """
    Extract raw TCP payload bytes from a scapy packet.
    Returns None if the packet has no TCP payload.
    """
    if pkt.haslayer(Raw):
        return bytes(pkt[Raw].load)
    return None
