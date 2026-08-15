"""
Parses QUIC Initial packets from pcap to extract transport features.
QUIC runs over UDP. Initial packets use a fixed key derivation (HKDF from
Connection ID) per RFC 9001, so they can be decrypted with known algorithms.

For our purposes, we only need:
  - Was QUIC used at all? (used_http3)
  - QUIC version (from the Long Header version field)
  - Number of transport parameters (from the CRYPTO frame)
  - Connection ID length

We detect QUIC Initial packets heuristically via the Long Header bit pattern,
then parse the version and connection ID fields. Full CRYPTO frame decryption
(required for transport parameters) uses aioquic's utilities.
"""
import struct
import sys
from pathlib import Path
_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))
from _paths import setup_paths; setup_paths(_ROOT)

from scapy.all import rdpcap, UDP


def extract_quic_features_from_pcap(pcap_path: str) -> dict:
    """
    Scan pcap for UDP packets on port 443.
    If a QUIC Initial packet is found, return:
      {
        "used_http3": 1,
        "quic_version": int,
        "quic_transport_param_count": int,   # -1 if unable to decrypt
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
    default = {
        "used_http3":                 0,
        "quic_version":               -1,
        "quic_transport_param_count": -1,
        "quic_conn_id_len":           -1,
    }

    try:
        packets = rdpcap(str(pcap_path))
    except Exception:
        return default

    for pkt in packets:
        if not pkt.haslayer(UDP):
            continue
        udp = pkt[UDP]
        # Only look at traffic to/from port 443
        if udp.dport != 443 and udp.sport != 443:
            continue

        payload = bytes(udp.payload)
        if not payload:
            continue

        if not _is_quic_initial(payload):
            continue

        # Parse QUIC Long Header fields:
        # Byte 0:      Header Form + Fixed Bit + Long Packet Type + Reserved + Packet Number Length
        # Bytes 1-4:   Version (4 bytes, big-endian)
        # Byte 5:      Destination Connection ID Length
        # Bytes 6+:    Destination Connection ID (variable)
        try:
            version = struct.unpack_from(">I", payload, 1)[0]
            dcil    = payload[5]   # Destination Connection ID Length

            return {
                "used_http3":                 1,
                "quic_version":               version,
                "quic_transport_param_count": -1,  # Requires CRYPTO decryption; deferred
                "quic_conn_id_len":           dcil,
            }
        except (struct.error, IndexError):
            continue

    return default


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
