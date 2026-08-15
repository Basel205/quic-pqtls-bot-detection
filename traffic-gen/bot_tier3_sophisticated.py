"""
Bot Tier 3 — Sophisticated bot using headless Playwright (real browser engine).

Characteristics:
  - Real Chrome browser engine (via Playwright) → WILL send 0x11EC PQ key share
  - WILL negotiate QUIC/HTTP3 (identical to human tier in protocol signals)
  - Detectable via behavioral features: fast uniform timing, no real interaction
  - Injects X-Session-ID header for JA4H correlation

This tier demonstrates that even a bot using a real browser can be detected
via behavioral timing signals, while also showing that PQ/QUIC features alone
are insufficient for Tier 3 (motivating the full feature set).

Label: "bot_t3"
"""
import asyncio
import random
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from traffic_gen.config import (
    TARGET_BASE_URL, TARGET_PAGES,
    BOT_DELAY_MEAN, BOT_DELAY_STD,
    SESSIONS_TIER3,
)

try:
    from playwright.async_api import async_playwright
except ImportError:
    print("ERROR: playwright not installed. Run: pip install playwright && playwright install chromium")
    sys.exit(1)


async def run_bot_t3_session(session_id: str) -> None:
    """
    Run a real headless Chrome browser but with bot-like (fast, uniform) timing.
    Uses the same real browser as human_traffic.py but with no human delays.
    """
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(
            extra_http_headers={"X-Session-ID": session_id},
            ignore_https_errors=True,
        )
        page = await context.new_page()

        for path in TARGET_PAGES:
            url = f"{TARGET_BASE_URL}{path}"
            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=10000)
            except Exception as e:
                print(f"  [bot_t3] {session_id} navigate error: {e}")

            # Bot-like timing: fast and uniform (contrast with human's variable delays)
            delay = max(0.01, random.gauss(BOT_DELAY_MEAN, BOT_DELAY_STD))
            await asyncio.sleep(delay)

        await context.close()
        await browser.close()


async def main(num_sessions: int = SESSIONS_TIER3) -> list[str]:
    session_ids = []
    for i in range(num_sessions):
        sid = str(uuid.uuid4())
        print(f"[bot_t3] Session {i+1}/{num_sessions} — {sid}")
        await run_bot_t3_session(sid)
        session_ids.append(sid)
    return session_ids


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--sessions", type=int, default=1)
    args = parser.parse_args()
    asyncio.run(main(args.sessions))
