"""
Wraps tshark to capture one pcap per session.
Called by session_orchestrator.py around each traffic generation run.
"""
import subprocess
import time
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from traffic_gen.config import TSHARK_BIN, TSHARK_INTERFACE, TSHARK_PORT


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
        stderr=subprocess.DEVNULL,
    )
    # Brief pause to let tshark start capturing before traffic begins
    time.sleep(0.5)
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
