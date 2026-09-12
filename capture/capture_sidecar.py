"""
Wraps tshark to capture one pcap per session.
Called by session_orchestrator.py around each traffic generation run.
"""
import subprocess
import threading
import time
from pathlib import Path

# Bootstrap paths
import sys
from pathlib import Path
_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))
from _paths import setup_paths; setup_paths(_ROOT)

from tg_config import TSHARK_BIN, TSHARK_INTERFACE, TSHARK_PORT


READY_TIMEOUT_SECONDS = 5.0  # max time to wait for tshark's capture-handle-open signal
POST_READY_BUFFER_SECONDS = 0.4  # extra margin after the signal — see note in start_capture()


def _drain_stderr(proc: subprocess.Popen, ready_event: threading.Event) -> None:
    """
    Continuously read tshark's stderr for the process's lifetime.
    Sets `ready_event` as soon as tshark signals its capture handle is open
    (the "Capturing on '...'" line it prints once Npcap is actually live —
    confirmed empirically on this machine). Keeps draining afterwards so the
    OS pipe buffer never fills and stalls tshark.
    """
    try:
        for line in iter(proc.stderr.readline, ""):
            if not ready_event.is_set() and "Capturing on" in line:
                ready_event.set()
    except (ValueError, OSError):
        pass  # stream closed under us when the process is torn down


def start_capture(
    session_id: str,
    pcap_dir: Path,
    interface: str,
    port: int,
    tshark_bin: str,
) -> subprocess.Popen:
    """
    Start a tshark process capturing on `interface`, filtered to `port`.
    Returns the Popen handle — caller is responsible for stopping it.
    Writes to: pcap_dir / f"{session_id}.pcap"

    tshark command:
      tshark -i {interface} -f "port {port}" -w {output_path} -q

    Blocks until tshark's Npcap capture handle is confirmed open (via its
    stderr "Capturing on ..." line) before returning, rather than a fixed
    sleep — a blind sleep raced ahead of tshark's actual startup latency for
    fast sessions (bot_t1/bot_t2), whose entire TCP+TLS handshake could
    complete before tshark was capturing, silently producing pcaps with no
    ClientHello at all. Falls back to a short sleep if the signal never
    arrives within READY_TIMEOUT_SECONDS, so capture still proceeds rather
    than hanging if tshark's output format ever changes.

    Also waits POST_READY_BUFFER_SECONDS after the signal: empirically, the
    "Capturing on" line prints as soon as tshark opens the Npcap handle, but
    packets don't start reaching the capture buffer until slightly after
    that (confirmed by re-running bot_t1/bot_t2 sessions back-to-back —
    later sessions in a batch skip the one-time Python module-import delay
    that accidentally covered this gap for the first session, and lost
    their ClientHello despite the readiness signal having already fired).
    """
    pcap_dir = Path(pcap_dir)
    pcap_dir.mkdir(parents=True, exist_ok=True)
    output_path = get_pcap_path(session_id, pcap_dir)

    cmd = [
        tshark_bin,
        "-i", interface,
        "-f", f"port {port}",
        "-w", str(output_path),
        "-q",
    ]

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    ready_event = threading.Event()
    drain_thread = threading.Thread(target=_drain_stderr, args=(proc, ready_event), daemon=True)
    drain_thread.start()

    if ready_event.wait(timeout=READY_TIMEOUT_SECONDS):
        time.sleep(POST_READY_BUFFER_SECONDS)
    else:
        time.sleep(0.5)  # readiness line never arrived — fall back to the old heuristic

    return proc


def stop_capture(proc: subprocess.Popen) -> None:
    """
    Gracefully terminate tshark. Wait up to 3 seconds, then kill if still running.
    """
    if proc.poll() is not None:
        # Already exited
        return
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def get_pcap_path(session_id: str, pcap_dir: Path) -> Path:
    """Returns the expected pcap file path for a session_id."""
    return Path(pcap_dir) / f"{session_id}.pcap"
