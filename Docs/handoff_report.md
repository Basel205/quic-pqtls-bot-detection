# QUIC-PQTLS Bot Detection — Project Handoff & Status Report

Welcome to the project! This document outlines exactly where the codebase currently stands, what has been implemented, and what the immediate next steps are so you can seamlessly pick up the work.

## 🎯 The Core Mission
We are building a system to test a novel hypothesis: **Can the recent rollout of Post-Quantum TLS (specifically the `0x11EC` / X25519MLKEM768 key exchange) and QUIC/HTTP-3 be used as new signals to detect advanced bots that already evade classical TLS/HTTP fingerprinting?**

## 📚 Essential Reading (The Docs)
Before writing any code, please review the authoritative plans in the `Docs/` folder:
1. **`MASTER_Implementation_Plan.md`**: **READ THIS FIRST**. It is the single source of truth for the architecture, build order, and the critical `0x11EC` codepoint rule.
2. `system_design_brief_COMPLETE.md`: Contains deeper technical specifications and component interactions.
3. `Project_Description_QUIC_PQTLS_Bot_Detection.md` & `Implementation_Spec_QUIC_PQTLS_Bot_Detection.md`: Earlier drafts that provide narrative and background context.

---

## ✅ What Is Done (Phases 0, 1, 2, and 3)
The complex infrastructure for traffic generation and packet parsing is completely written. 

### 1. Target Environment (`target-site/`)
- **Caddy Web Server**: Configured via `Caddyfile` to serve `localhost:443` using QUIC and Post-Quantum TLS (via `local_certs`). Generates JSON access logs.
- **Express Backend**: `server.js` hosts dummy endpoints (`/api/products`, `/api/login`) to act as the honeypot for our bots.

### 2. Feature Extraction Pipeline (`feature-extraction/`)
- **`pq_detector.py`**: Custom TLS parser using `scapy`. Correctly identifies the presence of the `0x11EC` group ID in the ClientHello.
- **`quic_parser.py`**: Heuristically detects QUIC Initial packets over UDP port 443.
- **`ja4_extractor.py` & `ja4h_extractor.py`**: Computes classical FoxIO network and HTTP fingerprints.
- **`timing_extractor.py`**: Extracts behavioral timing (e.g., Coefficient of Variation for inter-request gaps).
- **`build_dataset.py`**: Joins all extracted signals and outputs the final `dataset.parquet` and SQLite database.
- **`feature_schema.py`**: The authoritative 19-field schema used across the pipeline.

### 3. Traffic Generators (`traffic-gen/`)
- **`session_orchestrator.py`**: The runner that executes a session, triggers the `capture_sidecar.py` `tshark` packet sniffer, and records metadata to `session_manifest.csv`.
- **Bot Tiers**: Scripts for `human_traffic.py`, `bot_tier1_naive.py`, `bot_tier2_evasive.py` (which intentionally uses a pinned `curl_cffi` profile without PQ support), and `bot_tier3_sophisticated.py` are built. 
- *(Note: `bot_tier4_adaptive.py` is correctly left as a stub, as it is needed in Phase 5).*

---

## 🚧 What Is Left To Be Done (Phases 4, 5, and 6)

### Immediate Next Step: Generate the Dataset
The code to build the dataset is written, but **the script hasn't been run yet**.
- **Action**: Run the `session_orchestrator.py` script.
- **Goal**: Generate ~1,800 pcap files in `capture/pcap_store/`, and run `build_dataset.py` to create `dataset.parquet`.

### Phase 4: Machine Learning
The `ml/` directory has been scaffolded, and hyperparameter configurations are set in `ml/config.py`.
- **Action**: Implement `train_baseline.py` (using only classical features) and `train_enhanced.py` (incorporating PQ/QUIC features).
- **Goal**: Train XGBoost/CatBoost models, log metrics in MLflow, and prove the hypothesis (Experiment B > Experiment A). Generate SHAP feature importance plots.

### Phase 5: Evasion Testing (Tier 4)
- **Action**: Build `traffic-gen/bot_tier4_adaptive.py` using an OpenSSL 3.5 CLI client.
- **Goal**: Test how well the trained model holds up when an attacker actively fakes a PQ key share and QUIC protocol.

### Phase 6: Real-Time Detection Proxy & Dashboard
The `dashboard/` directory contains a raw Vite initialization.
- **Action**: Build a FastAPI real-time proxy that intercepts traffic, runs inference using the trained model in <200ms, and forwards safe traffic to Caddy.
- **Action**: Build the React dashboard to visualize live blocks and traffic streams.

---
*Generated: August 2026*
