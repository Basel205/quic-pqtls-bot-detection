"""
Bot Tier 4 — Adaptive/evasion bot: real headless Chrome, human-mimicking
timing, and a split backend-profile model. Implemented in Phase 5, after
Experiments A/B/D1/D2 were trained (per CLAUDE.md's Phase-gating rule) —
this is the "attacker has full knowledge of the feature set and deliberately
spoofs it" evasion test.

Design decision (documented here, same convention as Step 3's multi-hot
decision), deviating from the original stub's plan:

  The original stub called for an OpenSSL 3.5 CLI client to hand-craft a
  genuine PQ key share plus a forced QUIC stack via aioquic. That plan predates
  the Step 5/ML results below. bot_tier3_sophisticated.py already empirically
  proved a real headless Chromium engine (via Playwright) genuinely negotiates
  0x11EC PQ key share and QUIC/HTTP3 with zero bespoke protocol work — building
  a second, hand-rolled TLS/QUIC stack in OpenSSL would buy no extra realism
  over reusing that, and works against this project's "reuse, don't rebuild"
  principle. So Tier 4 is built the same way as Tier 3, plus two additions
  that directly target the two gaps the ML results exposed:

  1. Human-mimicking timing AND session length (HUMAN_DELAY_MEAN/STD,
     HUMAN_SESSION_REQS) instead of bot_tier3's fast/uniform bot timing. The
     B_enhanced confusion matrix showed timing was the *only* thing separating
     bot_t3 from human (1 misclassification out of 240, in bot_t3's favor) —
     an adaptive bot with "full knowledge of the feature set" would fix this
     first. This closes B's one remaining tell.

  2. A split backend-profile model *within* each client_identity_id
     repeat-visit group, instead of one deterministic tool/profile per tier
     (as tiers 1-3 all are — which is exactly why D2's temporal score is
     currently a flat 0.0 with nothing to detect, per CLAUDE.md). Each session
     is independently assigned one of two profiles:
       - "full":     default Chromium args → genuine PQ + QUIC, matches human
                      exactly at the protocol layer.
       - "degraded": Chromium launched with --disable-quic → falls back to
                      TLS1.3-over-TCP/h2, no QUIC at all (used_http3,
                      quic_version, quic_transport_param_count, and alpn_h3
                      all flip to their "absent" state).
     TIER4_DEGRADED_PROFILE_PROB (tg_config.py) sets the fraction that land on
     "degraded" — modeling a distributed bot operation where not every
     worker/exit-node in a claimed-identity group proxies QUIC's UDP traffic
     (a real constraint of many proxy/VPN providers). This is what gives D1 a
     realistic (not just theoretical) inconsistent combination to catch — per
     the Step 4 field-completeness check, 100% of human sessions in this
     dataset have PQ+QUIC, so a "degraded" session's combination has never
     been observed among human-labeled sessions — and gives D2 real
     cross-session drift within a client_identity_id group whenever a group
     contains a mix of both profiles. Whether a given identity-group happens
     to land all-"full" (fully evading D1+D2) or mixed (caught by one or both)
     is left to chance, same as it would be for a real bot operation — this is
     the "partial degradation is an expected and valid research finding" the
     original stub called for, made concrete.

Label: "bot_t4"
"""
import asyncio
import random
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from tg_config import (
    TARGET_BASE_URL, TARGET_PAGES,
    HUMAN_DELAY_MEAN, HUMAN_DELAY_STD,
    HUMAN_SESSION_REQS,
    SESSIONS_TIER4, TIER4_DEGRADED_PROFILE_PROB,
)

try:
    from playwright.async_api import async_playwright
except ImportError:
    print("ERROR: playwright not installed. Run: pip install playwright && playwright install chromium")
    sys.exit(1)


async def run_bot_t4_session(session_id: str, degraded: bool = False) -> None:
    """
    Run a real headless Chrome browser with human-mimicking timing/session
    length. `degraded=True` launches Chromium with --disable-quic, simulating
    a backend/exit-node in the bot operation that can't do QUIC — see module
    docstring. `degraded=False` ("full" profile) is protocol-indistinguishable
    from human_traffic.py.
    """
    launch_args = ["--disable-blink-features=AutomationControlled"]
    if degraded:
        launch_args.append("--disable-quic")

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True, args=launch_args)
        context = await browser.new_context(
            extra_http_headers={"X-Session-ID": session_id},
            ignore_https_errors=True,
        )
        page = await context.new_page()

        # Human-mimicking session length (matches human_traffic.py exactly —
        # this is the point: an adaptive bot copies the human distribution).
        n_requests = random.randint(*HUMAN_SESSION_REQS)
        pages_to_visit = random.choices(TARGET_PAGES, k=n_requests)

        for path in pages_to_visit:
            url = f"{TARGET_BASE_URL}{path}"
            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=10000)
            except Exception as e:
                print(f"  [bot_t4] {session_id} navigate error: {e}")

            # Human-mimicking delay (matches human_traffic.py exactly).
            delay = max(0.1, random.gauss(HUMAN_DELAY_MEAN, HUMAN_DELAY_STD))
            await asyncio.sleep(delay)

        await context.close()
        await browser.close()


async def main(num_sessions: int = SESSIONS_TIER4) -> list[str]:
    """
    Standalone run (no client_identity_id grouping awareness — that's the
    orchestrator's job, see session_orchestrator.py's per-session profile
    assignment). Each session independently gets the "degraded" profile with
    probability TIER4_DEGRADED_PROFILE_PROB. Returns list of session_ids.
    """
    session_ids = []
    for i in range(num_sessions):
        sid = str(uuid.uuid4())
        degraded = random.random() < TIER4_DEGRADED_PROFILE_PROB
        print(f"[bot_t4] Session {i+1}/{num_sessions} — {sid} (profile={'degraded' if degraded else 'full'})")
        await run_bot_t4_session(sid, degraded=degraded)
        session_ids.append(sid)
    return session_ids


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--sessions", type=int, default=1)
    args = parser.parse_args()
    asyncio.run(main(args.sessions))
