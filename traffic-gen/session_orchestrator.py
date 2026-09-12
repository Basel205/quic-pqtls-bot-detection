"""
Session Orchestrator — coordinates traffic generation, capture, and manifest.

Runs all traffic generator tiers sequentially, wrapping each session with:
  1. A capture_sidecar tshark process
  2. The traffic generator
  3. Manifest + DB writes

Usage:
  python session_orchestrator.py              # Full run per config.py session counts
  python session_orchestrator.py --mini       # 1 session per tier (Gate 2 smoke test)
  python session_orchestrator.py --tier human --sessions 5
"""
import argparse
import asyncio
import csv
import random
import sqlite3
import sys
import time
import uuid
from pathlib import Path

# Bootstrap paths
import sys
from pathlib import Path
_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))
from _paths import setup_paths; setup_paths(_ROOT)

from tg_config import (
    PCAP_STORE, DB_PATH, MANIFEST_PATH,
    TSHARK_BIN, TSHARK_INTERFACE, TSHARK_PORT,
    SESSIONS_HUMAN, SESSIONS_TIER1, SESSIONS_TIER2, SESSIONS_TIER3, SESSIONS_TIER4,
    TIER4_DEGRADED_PROFILE_PROB,
)
from capture_sidecar import start_capture, stop_capture, get_pcap_path
from init_db import init_db


# Tiers included in a bare `python session_orchestrator.py` full run (the main
# 1,600-session dataset). bot_t4 is intentionally excluded here — it's Phase
# 5's evasion test, generated separately via `--tier bot_t4` (see
# ALL_TIER_MAP below) so it never accidentally gets folded into a "full run".
TIER_MAP = {
    "human":  ("human",  SESSIONS_HUMAN),
    "bot_t1": ("bot_t1", SESSIONS_TIER1),
    "bot_t2": ("bot_t2", SESSIONS_TIER2),
    "bot_t3": ("bot_t3", SESSIONS_TIER3),
}

# Every tier this orchestrator knows how to run, for --tier's argparse choices
# and lookup. bot_t4 lives here only, not in TIER_MAP.
ALL_TIER_MAP = {
    **TIER_MAP,
    "bot_t4": ("bot_t4", SESSIONS_TIER4),
}

# Number of sessions sharing one client_identity_id, simulating repeat visits
# from the same claimed client (needed for the temporal-consistency check).
CLIENT_IDENTITY_GROUP_SIZE = (3, 5)


def _write_manifest_row(session_id: str, client_identity_id: str, label: str, start_ts: float, end_ts: float, pcap_path: Path) -> None:
    """Append a row to session_manifest.csv, creating it with headers if needed."""
    MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    is_new = not MANIFEST_PATH.exists()
    with open(MANIFEST_PATH, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["session_id", "client_identity_id", "label", "start_ts", "end_ts", "pcap_path"])
        if is_new:
            writer.writeheader()
        writer.writerow({
            "session_id":         session_id,
            "client_identity_id": client_identity_id,
            "label":              label,
            "start_ts":           start_ts,
            "end_ts":             end_ts,
            "pcap_path":          str(pcap_path),
        })


def _write_db_session(session_id: str, client_identity_id: str, label: str, start_ts: float, end_ts: float, pcap_path: Path) -> None:
    """Insert a row into the SQLite sessions table."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            """INSERT OR IGNORE INTO sessions (session_id, client_identity_id, label, start_ts, end_ts, pcap_path)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (session_id, client_identity_id, label, start_ts, end_ts, str(pcap_path)),
        )
        conn.commit()
    finally:
        conn.close()


def _verify_pcap(pcap_path: Path) -> bool:
    """Verify the pcap file exists and is non-empty."""
    return pcap_path.exists() and pcap_path.stat().st_size > 0


async def run_session(label: str, session_id: str, client_identity_id: str, degraded: bool = False) -> bool:
    """
    Run a single session for the given label tier.
    `client_identity_id` groups this session with others claiming to be the
    same client (repeat visits) — distinct from `session_id`, which is unique
    per connection.
    `degraded` only applies to bot_t4 — see bot_tier4_adaptive.py's module
    docstring for what the "degraded" backend profile means.
    Returns True if the pcap is non-empty (success).
    """
    pcap_path = get_pcap_path(session_id, PCAP_STORE)

    # Start capture
    proc = start_capture(session_id, PCAP_STORE, TSHARK_INTERFACE, TSHARK_PORT, TSHARK_BIN)
    start_ts = time.time()

    try:
        if label == "human":
            import human_traffic
            await human_traffic.run_human_session(session_id)

        elif label == "bot_t1":
            import bot_tier1_naive
            bot_tier1_naive.run_bot_t1_session(session_id)

        elif label == "bot_t2":
            import bot_tier2_evasive
            bot_tier2_evasive.run_bot_t2_session(session_id)

        elif label == "bot_t3":
            import bot_tier3_sophisticated
            await bot_tier3_sophisticated.run_bot_t3_session(session_id)

        elif label == "bot_t4":
            import bot_tier4_adaptive
            await bot_tier4_adaptive.run_bot_t4_session(session_id, degraded=degraded)

        else:
            raise ValueError(f"Unknown label: {label}")

    except Exception as e:
        print(f"  [orchestrator] ERROR in {label} session {session_id}: {e}")
    finally:
        # Give tshark a brief moment to flush the last packets
        time.sleep(0.5)
        stop_capture(proc)

    end_ts = time.time()

    # Write manifest + DB
    _write_manifest_row(session_id, client_identity_id, label, start_ts, end_ts, pcap_path)
    _write_db_session(session_id, client_identity_id, label, start_ts, end_ts, pcap_path)

    ok = _verify_pcap(pcap_path)
    status = "OK" if ok else "EMPTY PCAP"
    print(f"  [orchestrator] {label} {session_id[:8]} — {status} ({pcap_path.stat().st_size if ok else 0} bytes)")
    return ok


async def run_tier(label: str, num_sessions: int) -> tuple[int, int]:
    """
    Run all sessions for one tier. Sessions are grouped into batches of
    CLIENT_IDENTITY_GROUP_SIZE (3-5) sharing one client_identity_id, simulating
    repeat visits from the same claimed client (needed for the temporal-
    consistency check). Returns (success_count, total).
    """
    success = 0
    i = 0
    while i < num_sessions:
        client_identity_id = str(uuid.uuid4())
        group_size = min(random.randint(*CLIENT_IDENTITY_GROUP_SIZE), num_sessions - i)
        for _ in range(group_size):
            sid = str(uuid.uuid4())
            i += 1
            degraded = label == "bot_t4" and random.random() < TIER4_DEGRADED_PROFILE_PROB
            profile_note = f", profile={'degraded' if degraded else 'full'}" if label == "bot_t4" else ""
            print(f"\n[orchestrator] {label} session {i}/{num_sessions} — {sid} (client_identity_id={client_identity_id[:8]}{profile_note})")
            ok = await run_session(label, sid, client_identity_id, degraded=degraded)
            if ok:
                success += 1
    return success, num_sessions


async def main(args: argparse.Namespace) -> None:
    # Initialize DB first
    init_db()

    if args.mini:
        tiers = [(label, 1) for label in ["human", "bot_t1", "bot_t2", "bot_t3"]]
    elif args.tier:
        label, default_count = ALL_TIER_MAP[args.tier]
        tiers = [(label, args.sessions or default_count)]
    else:
        tiers = [(label, count) for label, (_, count) in TIER_MAP.items()]
        # Override with --sessions if given
        if args.sessions:
            tiers = [(label, args.sessions) for label, _ in tiers]

    total_success = 0
    total_sessions = 0

    for label, count in tiers:
        print(f"\n{'='*60}")
        print(f"[orchestrator] Starting tier: {label} ({count} sessions)")
        print(f"{'='*60}")
        ok, total = await run_tier(label, count)
        total_success += ok
        total_sessions += total
        print(f"[orchestrator] {label} done: {ok}/{total} pcaps non-empty")

    print(f"\n{'='*60}")
    print(f"[orchestrator] COMPLETE: {total_success}/{total_sessions} sessions successful")
    print(f"  Manifest: {MANIFEST_PATH}")
    print(f"  Pcap store: {PCAP_STORE}")

    # Gate check
    if total_success < total_sessions:
        n_empty = total_sessions - total_success
        print(f"\n  WARNING: {n_empty} session(s) produced empty pcaps.")
        print("  Check that tshark is running as Administrator and the interface is correct.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="QUIC/PQ-TLS Bot Detection — Session Orchestrator")
    parser.add_argument("--mini",     action="store_true", help="Run 1 session per tier (Gate 2 smoke test)")
    parser.add_argument("--tier",     choices=list(ALL_TIER_MAP.keys()), help="Run only this tier")
    parser.add_argument("--sessions", type=int, default=None, help="Override session count")
    args = parser.parse_args()
    asyncio.run(main(args))
