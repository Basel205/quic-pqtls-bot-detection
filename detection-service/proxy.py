"""
TCP passthrough detection proxy — implements MASTER_Implementation_Plan.md
§8's recommended fallback architecture directly (skipping the Python `ssl`
callback spike; that doc already flags passthrough as the safer default):
read the ClientHello off the raw socket (always plaintext, regardless of TLS
version), score it, and if allowed, relay the connection transparently to
Caddy, which performs the actual handshake. The proxy never terminates
TLS/QUIC itself.

NOT tested against a live Caddy instance or a real browser — I don't have
that environment. What IS verified: the ClientHello read/peek mechanics
(tested here against a local dummy echo server standing in for Caddy) and
the scoring pipeline (tested separately in scorer.py/feature_realtime.py
against a real trained model). Test against your actual Caddy before relying
on this for the live demo — start with `python detection-service/proxy.py
--target-port 443 --listen-port 8443` and confirm a real browser connecting
to :8443 still reaches your site and negotiates PQ+QUIC correctly through it.

QUIC/UDP is NOT handled by this proxy — it only intercepts the TCP
ClientHello. A full solution needs a second, UDP-side listener watching for
QUIC Initial packets on the same target port, which is a materially
different code path (see quic_parser.py) and is out of scope for this first
version — disclose this as a known limitation, not a silent gap.
"""
import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(_ROOT))
from feature_realtime import read_clienthello, extract_realtime_features
from scorer import score_session

RISK_BLOCK_THRESHOLD = 0.5  # risk_score above this blocks the connection — tune on real traffic
LATENCY_LOG = []


async def relay(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
        writer.close()


async def handle_connection(client_reader, client_writer, target_host: str, target_port: int,
                             on_decision=None):
    peer = client_writer.get_extra_info("peername")
    t0 = time.monotonic()
    try:
        raw_clienthello = await read_clienthello(client_reader)
        features = extract_realtime_features(raw_clienthello)
        result = score_session(features, client_identity_id=str(peer))
        latency_ms = (time.monotonic() - t0) * 1000
        LATENCY_LOG.append(latency_ms)

        decision = {
            "peer": str(peer),
            "predicted_label": result["predicted_label"],
            "risk_score": result["risk_score"],
            "latency_ms": round(latency_ms, 2),
            "blocked": result["risk_score"] > RISK_BLOCK_THRESHOLD,
        }
        print(f"[proxy] {decision}")
        if on_decision:
            on_decision(decision)

        if decision["blocked"]:
            client_writer.close()
            return

    except (ValueError, asyncio.TimeoutError, asyncio.IncompleteReadError) as e:
        # Not a parseable ClientHello (or timed out reading one) — fail OPEN
        # (relay through unscored) rather than break real traffic; log it as
        # a coverage gap to investigate, not a block decision.
        print(f"[proxy] could not score {peer}, relaying unscored: {e}")
        raw_clienthello = b""

    try:
        target_reader, target_writer = await asyncio.open_connection(target_host, target_port)
    except OSError as e:
        print(f"[proxy] could not reach target {target_host}:{target_port}: {e}")
        client_writer.close()
        return

    if raw_clienthello:
        target_writer.write(raw_clienthello)
        await target_writer.drain()

    await asyncio.gather(
        relay(client_reader, target_writer),
        relay(target_reader, client_writer),
    )


async def main(listen_port: int, target_host: str, target_port: int):
    async def handler(r, w):
        await handle_connection(r, w, target_host, target_port)

    server = await asyncio.start_server(handler, "0.0.0.0", listen_port)
    print(f"[proxy] listening on :{listen_port}, relaying to {target_host}:{target_port}")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen-port", type=int, default=8443)
    parser.add_argument("--target-host", default="127.0.0.1")
    parser.add_argument("--target-port", type=int, default=443)
    args = parser.parse_args()
    asyncio.run(main(args.listen_port, args.target_host, args.target_port))
