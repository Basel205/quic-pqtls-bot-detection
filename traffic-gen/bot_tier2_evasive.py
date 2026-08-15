"""
Bot Tier 2 — Evasive bot using curl_cffi with a pinned pre-ML-KEM Chrome profile.

GATE 1.5 VERIFIED — 2026-08-15:
  Profile: chrome110 (pre-dates Chrome's ML-KEM rollout in April 2024)
  curl_cffi version: 0.16.0
  Result: has_pq_keyshare=0, no 0x11EC in supported_groups or key_share
  Pcap: tests/gate1_5_chrome110.pcap

  DO NOT upgrade curl_cffi or change the profile without re-running Gate 1.5.
  Future curl_cffi releases may update the chrome110 profile and silently add
  ML-KEM support, which would break the Tier 2 experimental distinction.

Characteristics:
  - curl_cffi + chrome110: spoofs JA4/JA3 fingerprint to look like Chrome 110
  - NO 0x11EC PQ key share (verified above — this is what makes Tier 2 detectable)
  - NO QUIC/HTTP3 (curl_cffi uses TCP, not UDP)
  - Fast uniform timing (bot-like behavioral fingerprint)
  - Injects X-Session-ID header for JA4H log correlation

Research significance:
  This tier demonstrates that JA4 spoofing ALONE is insufficient for evasion
  once PQ/QUIC signals are added to the feature set. A Tier 2 bot looks
  indistinguishable from Chrome on classical TLS fingerprints but reveals
  itself via absence of 0x11EC — the core experimental finding of this project.

Label: "bot_t2"
"""
import random
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from traffic_gen.config import (
    TARGET_BASE_URL, TARGET_PAGES,
    BOT_DELAY_MEAN, BOT_DELAY_STD,
    SESSIONS_TIER2,
)

try:
    from curl_cffi import requests as cr
except ImportError:
    print("ERROR: curl_cffi not installed. Run: pip install curl-cffi")
    sys.exit(1)

# Pinned profile — DO NOT CHANGE without re-running tests/gate1_5_tier2_verify.py
# and confirming the new profile still returns has_pq_keyshare=0.
_CURL_CFFI_PROFILE   = "chrome110"
_CURL_CFFI_VERSION   = "0.16.0"  # version at time of Gate 1.5 verification


def run_bot_t2_session(session_id: str) -> None:
    """
    Fire HTTP requests against the target site using a Chrome-spoofed TLS stack.
    Uses the pinned chrome110 profile (pre-ML-KEM).
    """
    session = cr.Session(impersonate=_CURL_CFFI_PROFILE)

    # All requests carry the session ID for JA4H log correlation
    session.headers.update({"X-Session-ID": session_id})

    for path in TARGET_PAGES:
        url = f"{TARGET_BASE_URL}{path}"
        try:
            if path == "/api/login":
                session.post(
                    url,
                    json={"username": "testbot", "password": "password123"},
                    verify=False,
                    timeout=10,
                )
            else:
                session.get(url, verify=False, timeout=10)
        except Exception as e:
            print(f"  [bot_t2] {session_id[:8]} request error: {e}")

        # Uniform fast delay — bot-like timing fingerprint
        delay = max(0.01, random.gauss(BOT_DELAY_MEAN, BOT_DELAY_STD))
        time.sleep(delay)


def main(num_sessions: int = SESSIONS_TIER2) -> list[str]:
    session_ids = []
    for i in range(num_sessions):
        sid = str(uuid.uuid4())
        print(f"[bot_t2] Session {i+1}/{num_sessions} — {sid[:8]}")
        run_bot_t2_session(sid)
        session_ids.append(sid)
    return session_ids


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--sessions", type=int, default=1)
    args = parser.parse_args()
    main(args.sessions)
