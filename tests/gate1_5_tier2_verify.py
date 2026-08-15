"""
Gate 1.5 Smoke Test — Verify chrome110 profile does NOT send 0x11EC.

This must pass before bot_tier2_evasive.py is used for any session batch.
Run with: python tests/gate1_5_tier2_verify.py
"""
import subprocess
import sys
import time
import threading
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
TSHARK_BIN       = r"C:\Program Files\Wireshark\tshark.exe"
TSHARK_INTERFACE = r"\Device\NPF_Loopback"

PCAP_OUT = Path(__file__).parent / "gate1_5_chrome110.pcap"

def run_tshark():
    return subprocess.Popen(
        [TSHARK_BIN, "-i", TSHARK_INTERFACE, "-f", "port 443", "-w", str(PCAP_OUT), "-q"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )

def run_probe():
    time.sleep(1.0)  # Let tshark start
    from curl_cffi import requests as cr
    try:
        r = cr.get("https://localhost", impersonate="chrome110", verify=False, timeout=10)
        print(f"  Probe: HTTP {r.status_code}")
    except Exception as e:
        print(f"  Probe error: {e}")
    time.sleep(0.5)

if __name__ == "__main__":
    print("[Gate 1.5] Starting tshark capture...")
    proc = run_tshark()

    t = threading.Thread(target=run_probe)
    t.start()
    t.join()

    proc.terminate()
    proc.wait(timeout=3)

    print(f"[Gate 1.5] Capture saved to {PCAP_OUT} ({PCAP_OUT.stat().st_size} bytes)")
    print("[Gate 1.5] Checking for 0x11EC in ClientHello...")

    # Now parse the pcap
    sys.path.insert(0, str(Path(__file__).parent.parent / "feature-extraction"))
    sys.path.insert(0, str(Path(__file__).parent.parent))
    # Import using importlib since directory has hyphen
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "pq_detector",
        str(PROJECT_ROOT / "feature-extraction" / "pq_detector.py")
    )
    pq_mod = importlib.util.module_from_spec(spec)
    # Also load feature_schema for PQ_GROUP_ID
    spec2 = importlib.util.spec_from_file_location(
        "feature_schema",
        str(PROJECT_ROOT / "feature-extraction" / "feature_schema.py")
    )
    feat_mod = importlib.util.module_from_spec(spec2)
    spec2.loader.exec_module(feat_mod)
    sys.modules["feature_extraction"] = type(sys)('feature_extraction')
    sys.modules["feature_extraction.feature_schema"] = feat_mod
    spec.loader.exec_module(pq_mod)
    extract_pq_features_from_pcap = pq_mod.extract_pq_features_from_pcap

    feats = extract_pq_features_from_pcap(str(PCAP_OUT))
    has_pq = feats["has_pq_keyshare"]
    pq_len = feats["pq_keyshare_data_len"]

    print(f"\n  has_pq_keyshare:      {has_pq}")
    print(f"  pq_keyshare_data_len: {pq_len}")
    print(f"  tls_version:          {feats['tls_version']:#06x}")

    if has_pq == 0:
        print("\n[Gate 1.5] PASS — chrome110 does NOT send 0x11EC PQ key share.")
        print("           Tier 2 (curl_cffi + chrome110) is safe to use.")
    else:
        print("\n[Gate 1.5] FAIL — chrome110 DID send 0x11EC PQ key share!")
        print("           Do NOT use this profile for Tier 2.")
        print("           Try a different pinned profile (e.g., chrome107, chrome99).")
        sys.exit(1)
