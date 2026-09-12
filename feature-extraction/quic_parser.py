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
then parse the version and connection ID fields. Transport-parameter counting
decrypts the client's Initial packet(s) using aioquic's Initial-secret
derivation (RFC 9001 uses a public salt, not the server's private key, so
this works for any observer) and reassembles the CRYPTO stream to reach the
ClientHello's quic_transport_parameters extension (0x0039).
"""
import struct
import sys
from pathlib import Path
_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))
from _paths import setup_paths; setup_paths(_ROOT)

from scapy.all import rdpcap, UDP
from aioquic.buffer import Buffer
from aioquic.quic.crypto import CryptoPair
from aioquic.quic.packet import QuicPacketType, pull_quic_header

from pq_detector import parse_clienthello

QUIC_TRANSPORT_PARAMS_EXT = 0x0039

# QUIC frame types a client's first-flight Initial packet is expected to
# contain: PADDING, PING, CRYPTO. Any other frame type encountered means our
# simplified parser doesn't understand this packet's structure, so we stop
# rather than risk mis-parsing the remaining bytes.
_FRAME_PADDING = 0x00
_FRAME_PING    = 0x01
_FRAME_CRYPTO  = 0x06


def extract_quic_features_from_pcap(pcap_path: str) -> dict:
    """
    Scan pcap for UDP packets on port 443.
    If a QUIC Initial packet is found, return:
      {
        "used_http3": 1,
        "quic_version": int,
        "quic_transport_param_count": int,   # -1 if unable to decrypt/parse
        "quic_conn_id_len": int,
        "quic_alpn": list[str],              # ALPN offered in the QUIC ClientHello, [] if undecryptable
      }
    If no QUIC packets found:
      {
        "used_http3": 0,
        "quic_version": -1,
        "quic_transport_param_count": -1,
        "quic_conn_id_len": -1,
        "quic_alpn": [],
      }
    """
    default = {
        "used_http3":                 0,
        "quic_version":               -1,
        "quic_transport_param_count": -1,
        "quic_conn_id_len":           -1,
        "quic_alpn":                  [],
    }

    try:
        packets = rdpcap(str(pcap_path))
    except Exception:
        return default

    used_http3    = False
    quic_version  = -1
    quic_conn_id_len = -1
    client_initials: list[bytes] = []  # client->server Initial packets, in capture order

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
        if not used_http3:
            try:
                quic_version      = struct.unpack_from(">I", payload, 1)[0]
                quic_conn_id_len  = payload[5]
                used_http3        = True
            except (struct.error, IndexError):
                continue

        if udp.dport == 443:  # client -> server: part of the ClientHello flight
            client_initials.append(payload)

    if not used_http3:
        return default

    parsed_ch = _reassemble_quic_clienthello(client_initials)
    transport_param_count = -1
    quic_alpn: list[str] = []
    if parsed_ch is not None:
        quic_alpn = parsed_ch["alpn"]
        transport_param_count = 0
        for ext in parsed_ch["extensions"]:
            if ext["type"] == QUIC_TRANSPORT_PARAMS_EXT:
                transport_param_count = _count_transport_params(ext["data"])
                break

    return {
        "used_http3":                 1,
        "quic_version":               quic_version,
        "quic_transport_param_count": transport_param_count,
        "quic_conn_id_len":           quic_conn_id_len,
        # ALPN as offered in the QUIC-layer ClientHello (e.g. "h3") — separate
        # from pq_detector's TCP-layer ALPN, since a session can offer QUIC and
        # non-QUIC ALPN values on two different connections. build_dataset.py
        # merges both before computing the final multi-hot ALPN fields.
        "quic_alpn":                  quic_alpn,
    }


def _reassemble_quic_clienthello(client_initial_payloads: list[bytes]) -> dict | None:
    """
    Decrypt the client's Initial packet(s) and reassemble the CRYPTO stream to
    recover the embedded ClientHello, returning pq_detector.parse_clienthello's
    parsed dict. Returns None if decryption/parsing isn't possible — e.g. a
    Retry occurred (DCID/packet numbers reset) or the packet contains frame
    types this simplified parser doesn't handle.
    """
    if not client_initial_payloads:
        return None

    crypto: CryptoPair | None = None
    crypto_chunks: dict[int, bytes] = {}  # CRYPTO stream offset -> data

    for pn, raw in enumerate(client_initial_payloads):
        buf = Buffer(data=raw)
        start_off = buf.tell()
        try:
            header = pull_quic_header(buf)
        except Exception:
            continue
        if header.packet_type != QuicPacketType.INITIAL:
            continue

        if crypto is None:
            crypto = CryptoPair()
            try:
                # is_client=False derives the "client in" secret — the key
                # the client used to encrypt what it sends, which is what a
                # passive observer needs to decrypt it. RFC 9001 Initial
                # secrets derive from a public salt + the DCID, not any
                # private key, so this works without server cooperation.
                crypto.setup_initial(cid=header.destination_cid, is_client=False, version=header.version)
            except Exception:
                return None

        encrypted_off = buf.tell() - start_off
        end_off = start_off + header.packet_length
        try:
            _, payload, _ = crypto.decrypt_packet(raw[start_off:end_off], encrypted_off, pn)
        except Exception:
            continue

        try:
            for offset, data in _parse_crypto_frames(payload):
                crypto_chunks[offset] = data
        except Exception:
            continue

    if not crypto_chunks:
        return None

    # Reassemble the CRYPTO stream in offset order. A client's first flight
    # is contiguous from offset 0; anything else means our simplified
    # reassembly can't make sense of it.
    stream = bytearray()
    for offset in sorted(crypto_chunks):
        if offset != len(stream):
            return None
        stream.extend(crypto_chunks[offset])

    if not stream:
        return None

    # The CRYPTO stream carries the Handshake message body directly (no TLS
    # record-layer header). Wrap it in a synthetic record so we can reuse
    # pq_detector's existing handshake/extension parser.
    fake_record = b"\x16\x03\x03" + struct.pack(">H", len(stream)) + bytes(stream)
    try:
        return parse_clienthello(fake_record)
    except ValueError:
        return None


def _parse_crypto_frames(payload: bytes) -> list[tuple[int, bytes]]:
    """
    Parse QUIC frames from a decrypted Initial packet payload, extracting
    CRYPTO frames as (offset, data). Stops at the first unrecognized frame
    type — client first-flight Initial packets only carry PADDING/PING/CRYPTO
    in practice, so anything else means this packet isn't what we expect.
    """
    buf = Buffer(data=payload)
    chunks: list[tuple[int, bytes]] = []
    while not buf.eof():
        frame_type = buf.pull_uint_var()
        if frame_type == _FRAME_PADDING or frame_type == _FRAME_PING:
            continue
        elif frame_type == _FRAME_CRYPTO:
            offset = buf.pull_uint_var()
            length = buf.pull_uint_var()
            data = buf.pull_bytes(length)
            chunks.append((offset, data))
        else:
            break
    return chunks


def _count_transport_params(data: bytes) -> int:
    """Count (id, length, value) entries in a quic_transport_parameters extension body."""
    buf = Buffer(data=data)
    count = 0
    try:
        while not buf.eof():
            buf.pull_uint_var()               # param id
            length = buf.pull_uint_var()      # value length
            buf.pull_bytes(length)            # value
            count += 1
    except Exception:
        pass
    return count


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
