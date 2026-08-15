"""
Human traffic generator — uses Playwright with a real Chrome browser.

Key behavior:
  - Real Chrome engine → sends X25519MLKEM768 (0x11EC) PQ key share
  - Negotiates QUIC/HTTP3 if server supports it (Caddy does)
  - Human-like randomized timing (mean=2.5s, std=1.2s between requests)
  - Injects X-Session-ID header into every request for JA4H correlation

Label: "human"
"""
import asyncio
import random
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from traffic_gen.config import (
    TARGET_BASE_URL, TARGET_PAGES,
    HUMAN_DELAY_MEAN, HUMAN_DELAY_STD,
    HUMAN_SESSION_REQS,
    SESSIONS_HUMAN, MANIFEST_PATH, DB_PATH,
)

try:
    from playwright.async_api import async_playwright
except ImportError:
    print("ERROR: playwright not installed. Run: pip install playwright && playwright install chromium")
    sys.exit(1)


async def run_human_session(session_id: str) -> None:
    """
    Drive a real Chrome browser through the target site.
    Injects X-Session-ID header on all requests.
    """
    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=["--disable-blink-features=AutomationControlled"],
        )
        context = await browser.new_context(
            extra_http_headers={"X-Session-ID": session_id},
            ignore_https_errors=True,  # Trust Caddy's local cert
        )
        page = await context.new_page()

        # Randomize the number of pages visited per session
        n_requests = random.randint(*HUMAN_SESSION_REQS)
        pages_to_visit = random.choices(TARGET_PAGES, k=n_requests)

        for path in pages_to_visit:
            url = f"{TARGET_BASE_URL}{path}"
            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=10000)
            except Exception as e:
                print(f"  [human] {session_id} navigate error: {e}")

            # Human-like delay between page visits
            delay = max(0.1, random.gauss(HUMAN_DELAY_MEAN, HUMAN_DELAY_STD))
            await asyncio.sleep(delay)

        await context.close()
        await browser.close()


async def main(num_sessions: int = SESSIONS_HUMAN) -> list[str]:
    """
    Run `num_sessions` human traffic sessions sequentially.
    Returns list of session_ids generated.
    """
    session_ids = []
    for i in range(num_sessions):
        sid = str(uuid.uuid4())
        print(f"[human] Session {i+1}/{num_sessions} — {sid}")
        await run_human_session(sid)
        session_ids.append(sid)
    return session_ids


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--sessions", type=int, default=1)
    args = parser.parse_args()
    asyncio.run(main(args.sessions))
