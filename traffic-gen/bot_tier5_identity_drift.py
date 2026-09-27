"""
Bot Tier 5 — Identity-drift bot. Built to close the one remaining gap in the
evidence: every result so far (D2 beating B, the 34 named uncatchable
sessions, the AUC gap) comes from Tier 4, where ~30-35% of sessions are
individually "degraded" (PQ present, QUIC absent) — a single-session tell
that a sufficiently motivated real-world attacker could eventually just stop
doing. Tier 5 removes that tell entirely and isolates the temporal hypothesis
on its own:

  - EVERY session uses the "full" profile: real PQ + QUIC + human-mimicking
    timing, always. No --disable-quic, ever. Individually, every single
    Tier-5 session should be scored by A/B/D1 as indistinguishable from
    human — there is deliberately no per-session tell for them to find.

  - The only signal is genuine cross-session drift: sessions within the same
    client_identity_id group alternate between two real, separately-launched
    browser channels (Chromium's bundled build vs. the system-installed
    Google Chrome). Both are real Chrome-family browsers that independently
    negotiate PQ+QUIC correctly — but they're different binaries with
    different default cipher-suite/extension ordering, so they produce
    different ja4_fingerprint_hash values. A real human's browser doesn't
    silently swap its own TLS stack between visits; a distributed bot
    operation whose "identity" is actually served by more than one worker
    machine plausibly does. That's the same real-world justification Tier 4
    used for its degraded-profile mix, applied to the fingerprint dimension
    instead of the presence dimension.

Expected result if the temporal hypothesis is right: A_baseline, B_enhanced,
and D1_spatial should all evade at ~100% (nothing in a single session
distinguishes this from human — by design). D2_spatial_temporal should catch
a large fraction via the same cross-session mechanism already proven on
Tier 4, this time with no individual-session tell to fall back on. If D2's
evasion rate on Tier 5 is NOT dramatically better than B's, that's the
cleanest possible falsification of the hypothesis — this dataset is built
specifically so there's nowhere else for the improvement to come from.

REQUIRES: a system-installed Google Chrome, in addition to the Playwright-
bundled Chromium already used by tiers 3/4 (`playwright install chrome`).
Verify both channels launch and negotiate PQ+QUIC against your Caddy server
BEFORE running a full batch — this script has NOT been run against a live
server; it follows bot_tier4_adaptive.py's exact structure and API but the
actual JA4 delta between channels on YOUR Caddy/Chrome versions needs
confirming with a couple of manual test sessions first (see "Manual
verification" below).

Label: "bot_t5"
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
)

try:
    from playwright.async_api import async_playwright
except ImportError:
    print("ERROR: playwright not installed. Run: pip install playwright && playwright install chromium chrome")
    sys.exit(1)

# Fraction of sessions within a group that use the ALTERNATE channel (system
# Chrome) instead of the default (bundled Chromium). Mirrors
# TIER4_DEGRADED_PROFILE_PROB's role — add this constant to tg_config.py
# alongside it rather than hardcoding here, if you want it centrally tunable.
TIER5_ALT_CHANNEL_PROB = 0.4
SESSIONS_TIER5 = 200          # match Tier 4's scale; adjust as needed
TIER5_GROUP_SIZE_RANGE = (3, 5)  # sessions per client_identity_id, matches Tier 4's actual observed range


async def run_bot_t5_session(session_id: str, use_alt_channel: bool) -> None:
    """Always negotiates full PQ+QUIC — the only thing that varies between
    calls is which real browser channel launches, never protocol presence."""
    launch_args = ["--disable-blink-features=AutomationControlled"]
    launch_kwargs = {"headless": True, "args": launch_args}
    if use_alt_channel:
        launch_kwargs["channel"] = "chrome"  # system-installed Google Chrome

    async with async_playwright() as p:
        browser = await p.chromium.launch(**launch_kwargs)
        context = await browser.new_context(
            extra_http_headers={"X-Session-ID": session_id},
            ignore_https_errors=True,
        )
        page = await context.new_page()

        n_requests = random.randint(*HUMAN_SESSION_REQS)
        pages_to_visit = random.choices(TARGET_PAGES, k=n_requests)

        for path in pages_to_visit:
            url = f"{TARGET_BASE_URL}{path}"
            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=10000)
            except Exception as e:
                print(f"  [bot_t5] {session_id} navigate error: {e}")
            delay = max(0.1, random.gauss(HUMAN_DELAY_MEAN, HUMAN_DELAY_STD))
            await asyncio.sleep(delay)

        await context.close()
        await browser.close()


async def run_identity_group(client_identity_id: str, n_sessions: int) -> list[str]:
    """Runs one identity's repeat-visit sessions. At least one session in
    every group of size >= 2 is forced onto the alternate channel, so the
    dataset always has drift to detect within multi-session groups rather
    than leaving it to chance the way Tier 4 does for degraded profiles —
    change this back to a pure per-session coin flip (like Tier 4's
    TIER4_DEGRADED_PROFILE_PROB) if you want the same
    "some groups happen to fully evade" realism instead."""
    session_ids = [str(uuid.uuid4()) for _ in range(n_sessions)]
    alt_flags = [random.random() < TIER5_ALT_CHANNEL_PROB for _ in range(n_sessions)]
    if n_sessions >= 2 and not any(alt_flags):
        alt_flags[random.randrange(n_sessions)] = True

    for sid, use_alt in zip(session_ids, alt_flags):
        print(f"[bot_t5] identity={client_identity_id} session={sid} "
              f"(channel={'chrome' if use_alt else 'chromium'})")
        await run_bot_t5_session(sid, use_alt_channel=use_alt)

    return session_ids


async def main(num_sessions: int = SESSIONS_TIER5) -> list[str]:
    all_session_ids = []
    remaining = num_sessions
    while remaining > 0:
        group_size = min(random.randint(*TIER5_GROUP_SIZE_RANGE), remaining)
        identity = str(uuid.uuid4())
        ids = await run_identity_group(identity, group_size)
        all_session_ids.extend(ids)
        remaining -= group_size
    return all_session_ids


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--sessions", type=int, default=1)
    parser.add_argument("--manual-check", action="store_true",
                         help="Run ONE session on each channel and print nothing else — "
                              "use this first to confirm both channels launch and reach "
                              "your Caddy server before running a full batch.")
    args = parser.parse_args()

    if args.manual_check:
        async def _check():
            for use_alt in (False, True):
                sid = str(uuid.uuid4())
                print(f"Manual check — channel={'chrome' if use_alt else 'chromium'}, session={sid}")
                await run_bot_t5_session(sid, use_alt_channel=use_alt)
                print("  OK — check your Caddy access log / capture for this session_id "
                      "to confirm PQ+QUIC negotiated and note the ja4_fingerprint_hash.")
        asyncio.run(_check())
    else:
        asyncio.run(main(args.sessions))
