"""
JA4H HTTP request fingerprint extractor.

JA4H encodes the structure of the HTTP request (method, version, headers,
cookies presence) independently of payload content. It uses Caddy's JSON
access log as input rather than the pcap.

SESSION CORRELATION DESIGN:
Each traffic generator script MUST inject a custom HTTP header:
  X-Session-ID: <session_id>
into every request. Caddy logs all request headers in JSON format.
This extractor reads those log lines and matches on the session_id.

This is more reliable than timestamp+port correlation because:
  - Multiple sessions may be active concurrently
  - tshark timestamps and Caddy log timestamps may have sub-ms drift
  - Port numbers are recycled quickly in loopback traffic

The session_orchestrator.py passes session_id to each traffic generator,
which must include X-Session-ID in every outgoing request.
"""
import hashlib
import json
from pathlib import Path


def extract_ja4h(session_id: str, access_log_path: str) -> dict:
    """
    Scan Caddy's JSON access log for lines belonging to `session_id`
    (identified by the X-Session-ID request header).

    Returns:
      {
        "ja4h_fingerprint": str,        # full JA4H string
        "ja4h_fingerprint_hash": int,   # integer hash for ML
      }

    JA4H format (simplified, per FoxIO spec):
      {method}{http_version}{has_cookies}{num_headers}_{sorted_header_names_hash}
    """
    default = {"ja4h_fingerprint": "", "ja4h_fingerprint_hash": 0}

    log_path = Path(access_log_path)
    if not log_path.exists():
        return default

    # Find first log line matching this session_id
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

                request = entry.get("request", {})
                headers = request.get("headers", {})

                # Match on X-Session-ID header (case-insensitive key from Caddy)
                sid_values = headers.get("X-Session-Id", headers.get("X-Session-ID", []))
                if not sid_values:
                    continue
                if (isinstance(sid_values, list) and session_id not in sid_values):
                    continue
                if (isinstance(sid_values, str) and sid_values != session_id):
                    continue

                # Found matching request — compute JA4H
                method       = request.get("method", "GET")
                proto        = request.get("proto", "HTTP/1.1")
                has_cookies  = "1" if "Cookie" in headers or "cookie" in headers else "0"
                header_names = sorted(
                    k.lower() for k in headers.keys()
                    if k.lower() not in ("cookie", "x-session-id", "x-session-id")
                )
                num_headers  = len(header_names)

                # HTTP version string
                http_ver = proto.replace("HTTP/", "").replace(".", "")[:2].ljust(2, "0")

                # Hash of sorted header names
                hdr_str  = ",".join(header_names)
                hdr_hash = hashlib.sha256(hdr_str.encode()).hexdigest()[:12]

                ja4h = f"{method[:2].upper()}{http_ver}{has_cookies}{num_headers:02d}_{hdr_hash}"
                ja4h_int = int(hashlib.sha256(ja4h.encode()).hexdigest(), 16) % (2**31)
                return {"ja4h_fingerprint": ja4h, "ja4h_fingerprint_hash": ja4h_int}

    except OSError:
        return default

    return default
