"""
Bot Tier 1 — Naive bot using Python requests.

Characteristics:
  - No TLS fingerprint spoofing — uses Python's default ssl/urllib3 stack
  - No PQ key share (0x11EC absent — Python requests uses OpenSSL defaults
    which may not include ML-KEM depending on OpenSSL version)
  - No QUIC/HTTP3 (requests is HTTP/1.1 only)
  - Fast, uniform inter-request timing — low timing CV
  - Injects X-Session-ID header for JA4H correlation

Label: "bot_t1"
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
    SESSIONS_TIER1,
)

try:
    import requests
    import urllib3
    urllib3.disable_warnings()
except ImportError:
    print("ERROR: requests not installed. Run: pip install requests")
    sys.exit(1)


def run_bot_t1_session(session_id: str) -> None:
    """
    Fire HTTP requests against the target site as a naive bot.
    Hits all pages in order with minimal delay.
    """
    session = requests.Session()
    session.verify = False  # Accept Caddy's local cert

    # All requests carry the session ID for JA4H log correlation
    session.headers.update({
        "X-Session-ID": session_id,
        "User-Agent": "python-requests/2.32.0",  # Plain Python UA — highly bot-detectable
    })

    for path in TARGET_PAGES:
        url = f"{TARGET_BASE_URL}{path}"
        try:
            if path == "/api/login":
                session.post(url, json={"username": "testbot", "password": "password123"})
            else:
                session.get(url)
        except Exception as e:
            print(f"  [bot_t1] {session_id} request error: {e}")

        # Uniform low delay — bot-like timing fingerprint
        delay = max(0.01, random.gauss(BOT_DELAY_MEAN, BOT_DELAY_STD))
        time.sleep(delay)

    session.close()


def main(num_sessions: int = SESSIONS_TIER1) -> list[str]:
    session_ids = []
    for i in range(num_sessions):
        sid = str(uuid.uuid4())
        print(f"[bot_t1] Session {i+1}/{num_sessions} — {sid}")
        run_bot_t1_session(sid)
        session_ids.append(sid)
    return session_ids


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--sessions", type=int, default=1)
    args = parser.parse_args()
    main(args.sessions)
