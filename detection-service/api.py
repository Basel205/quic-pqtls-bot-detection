"""
FastAPI + WebSocket backend for the live dashboard. Broadcasts each proxy
decision to connected dashboard clients in real time.

NOT tested end-to-end with a live proxy feeding it (proxy.py currently
prints decisions to stdout via its `on_decision` hook, which needs wiring to
call broadcast() here instead — a few lines, not done in this pass given
time spent verifying the higher-priority pieces above). Import-tested only:
this starts cleanly and the REST endpoints respond; the WebSocket broadcast
path itself needs a real proxy run to exercise.
"""
import asyncio
import json
from collections import deque

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="QUIC-PQTLS Bot Detection — Live Feed")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

_connections: set[WebSocket] = set()
_recent_decisions = deque(maxlen=200)  # for a dashboard that connects mid-stream


@app.get("/health")
def health():
    return {"status": "ok", "connected_dashboards": len(_connections)}


@app.get("/recent")
def recent(limit: int = 50):
    return list(_recent_decisions)[-limit:]


@app.websocket("/ws/live")
async def live_feed(ws: WebSocket):
    await ws.accept()
    _connections.add(ws)
    try:
        while True:
            await ws.receive_text()  # keepalive/ignored; server is push-only
    except WebSocketDisconnect:
        _connections.discard(ws)


async def broadcast(decision: dict):
    """Call this from proxy.py's on_decision hook for each scored session."""
    _recent_decisions.append(decision)
    dead = set()
    for ws in _connections:
        try:
            await ws.send_text(json.dumps(decision))
        except Exception:
            dead.add(ws)
    _connections.difference_update(dead)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
