# Consistency-Aware Bot Detection over Next-Generation Network Protocols

This repository contains the data generation and feature extraction pipeline for evaluating consistency-based bot detection over next-generation protocol signals (PQ-TLS, QUIC, and HTTP/3).

The infrastructure (Phases 1-3) is fully complete. This includes the target site, the 4-tier bot traffic generator, packet capture sidecar, and the JA4/PQ/QUIC feature extraction pipeline.

## 🚀 Teammate Handoff & Setup Guide

This project is built for **Windows** (due to the specific Wireshark Npcap Loopback adapter requirements for capturing localhost traffic). Please follow these steps exactly to reproduce the lab environment.

### 1. Prerequisites
Before cloning, ensure you have the following installed on your Windows machine:
- **Python 3.11+**
- **Node.js** (v18+ recommended)
- **Caddy** (Add the `caddy` executable to your System PATH)
- **Wireshark / Npcap**: 
  - Install [Wireshark](https://www.wireshark.org/download.html).
  - **CRITICAL:** During the Npcap installation step, you **must** check the box that says **"Support loopback traffic (`\Device\NPF_Loopback`)"**. If you missed this, reinstall Npcap.

### 2. Clone the Repository
```bash
git clone https://github.com/Basel205/quic-pqtls-bot-detection.git
cd quic-pqtls-bot-detection
```

### 3. Python Environment Setup
We recommend creating a virtual environment for the project.
```bash
python -m venv venv
venv\Scripts\activate
```

Install the base requirements and specific packages needed for the traffic generators:
```bash
pip install -r requirements.txt

# Install the correct version of curl-cffi for Tier 2 evasive bots.
# We explicitly use 0.16.0 because its "chrome110" profile has been verified
# to NOT send the PQ-TLS 0x11EC key share (Gate 1.5 verified).
pip install curl-cffi==0.16.0

# Install Playwright browsers (needed for Tier 3 and Human traffic)
playwright install chromium
```

### 4. Start the Target Site (Backend & Caddy)
The lab requires a local NodeJS backend sitting behind Caddy (which provides the QUIC/HTTP3 and PQ-TLS termination). 

Open a **new terminal window** (keep it open) and start the Node backend:
```bash
cd target-site
npm install
node server.js
```

Open a **second terminal window** (keep it open) and start Caddy. 
*Note: Caddy will automatically generate local SSL certificates. If Windows prompts you for an Administrator password to install the local root trust certificate, accept it.*
```bash
cd target-site
caddy run
```

### 5. Verify the Capture Interface
Our capture script (`capture/capture_sidecar.py`) uses `tshark` (Wireshark's CLI) and listens on `\Device\NPF_Loopback`. 
Ensure `tshark.exe` exists at `C:\Program Files\Wireshark\tshark.exe`. If you installed it elsewhere, update `capture/config.py` (which is actually `tg_config.py` in `traffic-gen/`).

### 6. Run Gate 2 Smoke Test (End-to-End Verification)
Gate 2 is an end-to-end smoke test that fires 1 session per bot tier, captures the `.pcap` files, and saves them to `capture/pcap_store/`.

Open a **third terminal window**, activate your virtual environment, and run the session orchestrator:
```bash
python traffic-gen/session_orchestrator.py --mini
```

**Expected Output:**
You should see output indicating that `human`, `bot_t1`, `bot_t2`, and `bot_t3` sessions ran successfully and generated non-empty PCAP files. 

If you see `EMPTY PCAP` errors, it means `tshark` failed to capture traffic. You likely need to run your terminal as **Administrator** to grant Npcap permissions, or you didn't install Npcap loopback support.

---

## 📂 Project Structure
- `target-site/` - The Caddy proxy and Node.js dummy application.
- `traffic-gen/` - The bot scripts (Naive, Evasive, Sophisticated, Adaptive) and `session_orchestrator.py`.
- `capture/` - Contains the `capture_sidecar.py` wrapper and the `.pcap` outputs.
- `feature-extraction/` - Contains parsing logic for `0x11EC` presence (`pq_detector.py`), QUIC parser, timing, and JA4 extractors.
- `db/` - Contains the SQLite schema and initialization script.

## ⏭️ Next Steps for the Team
The data collection and feature extraction infrastructure is built. The next steps according to the project brief are:
1. Generate a large, diverse dataset of Human traffic using `session_orchestrator.py`. (You may need to modify `human_traffic.py` to use multiple browsers/OSes to get a rich baseline).
2. Use this baseline to build the **Expected-Combination Tables** (Spatial/Temporal consistency layers).
3. Implement the Consistency-Scoring model (`Model D`) and compare it against the Presence-only model (`Model B`).
