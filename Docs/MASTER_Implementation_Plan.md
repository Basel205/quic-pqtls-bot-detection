# MASTER IMPLEMENTATION PLAN — READ THIS FIRST, THIS IS THE AUTHORITATIVE DOCUMENT
## Next-Generation Protocol Fingerprinting for Robust Bot Detection
### BTech CSE Semester 7 Project — Basel Ali Khan

> **To whoever/whatever is building this (including Antigravity):** this document supersedes `Project_Description_QUIC_PQTLS_Bot_Detection.md` and `Implementation_Spec_QUIC_PQTLS_Bot_Detection.md` wherever they conflict. Those two remain useful for extra narrative/architecture detail but this file is the single source of truth for facts, schemas, and build order. If anything here contradicts them, follow this file.

---

## 1. What We're Building, In One Paragraph

A system that studies whether two recent internet protocol shifts — post-quantum TLS key exchange (X25519MLKEM768, rolled out 2024-2026) and QUIC/HTTP-3 adoption — can be used as new signals to detect bot traffic that already evades classical TLS/HTTP fingerprinting. We build a controlled lab environment, generate labeled human and bot traffic across multiple sophistication tiers, extract protocol-level features, train and compare classifiers (baseline vs. enhanced with the new signals), test how well the advantage survives an adaptive attacker, and wrap the result in a live, real-time detection proxy with a dashboard — producing both a publishable empirical result and a patent-eligible working system.

---

## 2. Why This Topic — Verified Novelty (do not deviate from this core claim)

Checked directly against current literature, not assumed:
- No academic paper evaluates PQ key-share presence as a bot-detection feature. Industry blogs discuss it; no formal study does.
- No academic paper evaluates QUIC/HTTP-3 handshake fingerprinting for bot detection specifically (existing QUIC fingerprinting research targets website-identification privacy attacks, a different problem).
- A February 2026 paper on JA4-based bot detection explicitly names HTTP/3 extension as unresolved future work.
- **This is the core novel contribution. Do not let it get diluted or replaced by other signal layers — those are supplementary, not the headline.**

**Supplementary signal layer (optional, pending team confirmation with teammate Akshat):** HTTP/2 SETTINGS-frame fingerprinting may be added as an additional feature layer. Note honestly: this specific technique is NOT novel — it's been commercial industry-standard since 2017 (Akamai). If added, it strengthens the feature set and gives a well-established baseline to compare against, but it must not be framed as part of the novel contribution in the paper.

---

## 3. CRITICAL TECHNICAL CORRECTION — READ BEFORE WRITING `pq_detector.py`

The correct, IANA-registered, standardized codepoint for the X25519MLKEM768 post-quantum key exchange group is **`0x11EC`** (4588 decimal).

**Do NOT use `0x6399`** — that is `X25519Kyber768Draft00`, a retired pre-standardization draft codepoint used experimentally by Chrome/Edge in 2023-2024. It is superseded and will not appear in current (2025-2026) browser traffic. Any detector checking for `0x6399` will silently fail to detect real, current PQ key shares and invalidate the entire core result.

PQ key share payload length: expect approximately **1216 bytes** (not 1180 as an earlier draft of this plan estimated). Confirm the exact value empirically against your own Phase 1 capture rather than hardcoding either number blindly.

---

## 4. System Architecture

```
Human Traffic (Playwright: Chrome/Firefox)        Bot Traffic (Tiers 1-4)
              │                                              │
              └──────────────────┬───────────────────────────┘
                                  ▼
                    Session Orchestrator (manifest: session_id, label, timestamp)
                                  ▼
                    TARGET SITE — Caddy (QUIC + PQ-TLS, localhost, self-signed via `caddy trust`)
                                  ▼ (passive tshark capture on loopback)
                    Capture Sidecar (one pcap per session_id)
                                  ▼
                    Feature Extraction (JA4, JA4H, PQ detector [0x11EC], QUIC parser, timing)
                                  ▼
                    Dataset Builder → dataset.parquet (19-field schema, see §6)
                                  ▼
                    ML Pipeline (MLflow-tracked: Experiments A/B/C, see §7)
                                  ▼ trained model
                    LIVE DETECTION PROXY (see §8 — architecture still needs verification spike)
                                  ▼
                    FastAPI + WebSocket → React Dashboard (live feed, charts)
```

---

## 5. Tech Stack (Locked)

| Layer | Tool |
|---|---|
| Web server | Caddy v2.8+ (native QUIC + x25519mlkem768) |
| Target site app | Node.js + Express (home, /products, /search, /login, /profile) |
| Human traffic | Playwright (Python), real Chrome + Firefox |
| Bot Tier 1 (naive) | requests, httpx |
| Bot Tier 2 (evasive) | curl-impersonate / tls-client |
| Bot Tier 3 (sophisticated) | Headless Playwright |
| Bot Tier 4 (adaptive/evasion) | OpenSSL 3.5 CLI-based client with genuine PQ key share |
| Packet capture | tshark (primary), scapy (parsing) |
| Fingerprinting | JA4 + JA4H (FoxIO open-source) |
| Feature pipeline | Python, pandas, pyarrow |
| Experiment tracking | MLflow (local) |
| ML | XGBoost + CatBoost (primary), Logistic Regression + Random Forest (baseline comparison) |
| Detection proxy | Python asyncio (architecture TBD — see §8) |
| Backend API | FastAPI + WebSockets |
| Dashboard | React + Recharts + Vite |
| Storage | SQLite + Parquet |
| Reproducibility | Zenodo dataset release (DOI) |

**Cost: $0 for all engineering.** Runs entirely on localhost, no domain or cloud required. Only conference/journal submission fees are a real cost — check with your guide/department on coverage.

---

## 6. Canonical Feature Schema (Final — `feature_schema.py` must implement exactly)

| Field | Type | Notes |
|---|---|---|
| session_id | string | — |
| ja4_fingerprint | string (hash) | — |
| ja4h_fingerprint | string (hash) | supplementary layer |
| tls_version | categorical | — |
| cipher_suite_count | int | — |
| cipher_suite_order_hash | string | — |
| extension_count | int | — |
| extension_order_hash | string | — |
| supported_groups | multi-hot | — |
| **has_pq_keyshare** | bool | **CORE NOVEL — check group ID 0x11EC** |
| pq_keyshare_data_len | int, nullable | expect ~1216 bytes |
| alpn_protocols | multi-hot | — |
| **used_http3** | bool | **CORE NOVEL** |
| quic_version | categorical, nullable | — |
| quic_transport_param_count | int, nullable | — |
| quic_conn_id_len | int, nullable | — |
| record_layer_timing_p50 | float, nullable | — |
| inter_request_timing_cv | float | supplementary — do not let this dominate the model |
| session_request_count | int | — |
| label | categorical | human / bot_tier1 / bot_tier2 / bot_tier3 / bot_tier4 |

**Never use:** User-Agent, IP, geo-data, cookies, payload content — trivially spoofable or privacy-sensitive.

---

## 7. Dataset Target and ML Experiment Design

| Class | Sessions | 
|---|---|
| human | 500 |
| bot_tier1 | 400 |
| bot_tier2 | 400 |
| bot_tier3 | 300 |
| bot_tier4 | 200 |
| **Total** | **~1,800**, 70/15/15 stratified split |

| Experiment | Feature Set | Purpose |
|---|---|---|
| A — Baseline | JA4 + classical TLS only | Control |
| B — Enhanced | + PQ + QUIC + timing (+ HTTP/2 if added) | Treatment — headline result |
| C — Ablation | B minus timing features | Isolates pure PQ/QUIC contribution — answer this in the paper, not the rebuttal |

Outputs required: Accuracy, Macro-F1, ROC-AUC, confusion matrices, B-minus-A delta table, SHAP feature importance plot.

**Evasion testing:** Tier 4 bot uses genuine OpenSSL 3.5 PQ key share + forced QUIC. Measure how much detection accuracy survives — report honestly, partial degradation is a valid finding.

---

## 8. OPEN ITEM — Verify Before Building the Detection Proxy

The live-proxy architecture (Phase 6) has an unresolved design question: does Python's `ssl` module actually expose raw ClientHello bytes via a documented callback (as an earlier draft assumed), or is that not achievable with the standard library?

**Do a short verification spike before committing to an approach.** If the callback approach doesn't hold up, use this fallback, which is architecturally safer and doesn't require reimplementing TLS: a raw TCP/UDP passthrough proxy that reads the ClientHello record directly off the socket (always sent in plaintext, regardless of TLS version), parses it for features, decides allow/block, and if allowed, transparently relays bytes onward to Caddy, which performs the actual handshake. This mirrors how real TLS-passthrough proxies (e.g., HAProxy SNI routing) work, and avoids the proxy needing to terminate TLS/QUIC itself.

---

## 9. Build Order and Gates

**Phase 0 (Day 1-2):** Environment setup — Caddy, Python venv, tshark, `caddy trust`. Gate: `https://localhost` loads without cert warning.

**Phase 1 (Week 1) — DO NOT SKIP:** Confirm via Wireshark/tshark that QUIC negotiates and that the ClientHello contains group ID `0x11EC`. This validates the entire project's premise before anything else is built.

**Phase 2 (Weeks 2-4):** Traffic generation (all 4 tiers) + capture sidecar + session orchestrator. Gate: 1,800+ labeled sessions, all pcaps non-zero.

**Phase 3 (Weeks 4-5):** Feature extraction pipeline (using corrected codepoint) + dataset builder. Gate: `dataset.parquet` with all 19 fields populated.

**Phase 4 (Weeks 5-6):** MLflow setup, train Experiments A/B/C, evaluate, SHAP plot. Gate: Experiment B F1 > Experiment A F1.

**Phase 5 (Week 7):** Build and run Tier 4 adaptive bot, evasion analysis. Gate: results drafted.

**Phase 6 (Weeks 8-9):** Resolve §8 open item, build proxy + scorer + FastAPI + React dashboard. Gate: live demo, blocks appear in real time, sub-200ms.

**Phase 7 (Weeks 9-12):** `run_all.sh`, README, full paper draft, Zenodo upload, provisional patent draft if pursuing.

---

## 10. Patent Claim Language (if pursuing)

**Claim 1 (Method):** A method for real-time bot detection comprising: (a) intercepting a TLS ClientHello from a client connection; (b) extracting the presence and byte-length of a post-quantum key encapsulation mechanism group identifier from the supported_groups and key_share extensions; (c) determining whether the connection was initiated over the QUIC transport protocol; (d) combining these features with classical TLS fingerprint features in a gradient-boosted classifier trained on labeled human and bot traffic; and (e) returning an allow or block decision based on the classifier output.

**Claim 2 (System):** A system implementing Claim 1, comprising a TLS-intercepting reverse proxy and a real-time feature extraction and inference pipeline with end-to-end latency under 200 milliseconds.

---

## 11. Definition of Done

- [ ] Caddy confirmed serving with correct PQ-TLS (0x11EC) + QUIC
- [ ] 1,800+ session labeled dataset
- [ ] All 19 features extracted and validated
- [ ] Experiment A/B/C results in MLflow, reproducible with fixed seeds
- [ ] SHAP importance plot generated
- [ ] Evasion Tier 4 results measured and reported honestly
- [ ] Live proxy blocking in real time, sub-200ms, architecture per §8
- [ ] Dashboard with live feed + comparison charts
- [ ] One-command startup (`run_all.sh`)
- [ ] Paper draft submitted to guide
- [ ] Zenodo dataset DOI obtained
- [ ] Clean, professional GitHub repo
