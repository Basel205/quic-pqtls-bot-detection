# Implementation Specification
# Next-Generation Protocol Fingerprinting for Robust Bot Detection

This is the complete engineering build spec. It covers every component that gets coded, in what order, using what tools, with what interfaces between them. This is the final architecture, not a prototype to be redone later — later work should extend this, not replace it.

---

## 1. System Architecture

```
                                        ┌─────────────────────────┐
                                        │   Human Traffic Gen      │
                                        │   (Playwright: real      │
                                        │   Chrome/Firefox)        │
                                        └───────────┬──────────────┘
                                                     │
┌─────────────────────────┐                         │
│   Bot Traffic Gen        │                         │
│   Tier 1/2/3 scripts     │                         │
└───────────┬──────────────┘                         │
            │                                        │
            ▼                                        ▼
     ┌──────────────────────────────────────────────────────┐
     │        TARGET SITE (Caddy, QUIC + PQ-TLS enabled)      │
     │        localhost / self-signed cert via caddy trust    │
     └──────────────────────────────────────────────────────┘
                              ▲
                              │  (passive capture, same interface)
                              │
                    ┌─────────────────────┐
                    │  Capture Sidecar      │
                    │  (tshark/scapy,       │
                    │  tags by session)     │
                    └──────────┬────────────┘
                               │ raw pcap + session metadata
                               ▼
                    ┌─────────────────────┐
                    │ Feature Extraction    │
                    │ (JA4, QUIC params,    │
                    │ PQ key-share detect)  │
                    └──────────┬────────────┘
                               │ feature vectors → SQLite
                               ▼
                    ┌─────────────────────┐
                    │  Dataset Builder      │
                    └──────────┬────────────┘
                               │ labeled dataset (parquet/csv)
                               ▼
                    ┌─────────────────────┐
                    │  ML Training +        │
                    │  Evaluation +         │
                    │  Evasion Testing       │
                    └──────────┬────────────┘
                               │ trained model artifact
                               ▼
     ┌──────────────────────────────────────────────────────┐
     │       LIVE DETECTION SERVICE (real-time proxy)         │
     │  Client → Detection Proxy → score → allow/block →      │
     │  forward to Caddy (target site)                        │
     └───────────────────────┬──────────────────────────────┘
                              │ live scores, stats
                              ▼
                    ┌─────────────────────┐
                    │   Dashboard (React)   │
                    │   Live feed + charts  │
                    └─────────────────────┘
```

---

## 2. Full Tech Stack

| Layer | Tool | Why |
|---|---|---|
| Web server (target site) | Caddy | Native QUIC + PQ-TLS (x25519mlkem768) by default, zero custom builds |
| Target site app | Node.js + Express, or plain static + a few dynamic routes | Realistic enough surface (login, search, listing) without overbuilding |
| Human traffic | Playwright (Python) | Drives real Chrome/Firefox — real handshakes, not simulated |
| Bot traffic (Tier 1) | `requests`, `httpx`, `curl` | Naive baseline bots |
| Bot traffic (Tier 2) | `curl-impersonate`, `tls-client` (Go-based) | JA3/JA4-spoofing bots — the interesting middle tier |
| Bot traffic (Tier 3) | Headless Playwright/Puppeteer | Sophisticated bots using real browser engines |
| Packet capture | `tshark`, `scapy` (Python) | Passive capture of TLS ClientHello + QUIC Initial packets |
| Fingerprinting | JA4 (FoxIO, open-source core) | Standard, extensible fingerprint format |
| Feature/data pipeline | Python, `pandas`, `pyarrow` | Standard tabular data tooling |
| Storage | SQLite | Zero-config, sufficient scale, easy to inspect |
| ML | `scikit-learn`, `XGBoost`, `CatBoost` | CPU-only, fast, matches your ModelGuard FraudClassifier experience |
| Detection proxy | Python (`asyncio` + `mitmproxy`-style raw socket handling) or Go | Go preferred if comfortable — better fit for high-throughput proxying; Python acceptable and faster to build |
| Dashboard | React + Recharts | Matches your existing portfolio style (ModelGuard) |
| Backend API for dashboard | FastAPI | Simple, async, pairs well with Python ML stack |
| Orchestration | `docker-compose` or a `run_all.sh` script | One-command spin-up for demo day |

---

## 3. Repository Structure

```
quic-pqtls-bot-detection/
├── README.md
├── docker-compose.yml
├── run_all.sh
├── target-site/                  # the honeypot site
│   ├── Caddyfile
│   ├── app/                      # Node/Express app (login, search, listing pages)
│   └── certs/                    # local CA output (gitignored)
├── traffic-gen/
│   ├── human_traffic.py
│   ├── bot_tier1_naive.py
│   ├── bot_tier2_evasive.py
│   ├── bot_tier3_sophisticated.py
│   └── session_orchestrator.py   # coordinates gen + capture + labeling
├── capture/
│   ├── capture_sidecar.py        # tshark/scapy wrapper, tags sessions
│   └── pcap_store/                # raw captures (gitignored, sampled subset committed)
├── feature-extraction/
│   ├── ja4_extractor.py
│   ├── quic_parser.py
│   ├── pq_detector.py
│   ├── feature_schema.py         # canonical feature vector definition
│   └── build_dataset.py
├── ml/
│   ├── train_baseline.py         # JA4 + HTTP-only features
│   ├── train_enhanced.py         # + PQ + QUIC features
│   ├── evaluate.py               # accuracy/F1/ROC-AUC/confusion matrix, delta report
│   ├── evasion_test.py           # adaptive bot vs. trained model
│   └── model_registry/           # versioned saved models
├── detection-service/
│   ├── proxy.py                  # the live scoring reverse proxy
│   ├── scorer.py                 # loads model, scores incoming sessions
│   └── api.py                    # FastAPI endpoints for dashboard
├── dashboard/
│   ├── src/
│   └── package.json
├── db/
│   └── schema.sql
├── tests/
│   ├── test_feature_extraction.py
│   ├── test_scorer.py
│   └── test_proxy.py
└── docs/
    ├── architecture.md
    └── setup.md
```

---

## 4. Component Specs

### 4.1 Target Site (`target-site/`)
- Caddy config (`Caddyfile`): serve the app over HTTPS on localhost, run `caddy trust` once to install the local CA so Chrome/Firefox don't flag it.
- App: 4-5 pages minimum — home, product listing (paginated, so bots have a reason to crawl), search (form-based), login (form-based, fake auth). Purpose is to give bots realistic behavior to exhibit, not to be a real product.
- Confirm in Phase 1 smoke test: QUIC negotiates, PQ key share appears in ClientHello. This gates everything downstream — do not proceed to Phase 2 until this is confirmed.

### 4.2 Traffic Generation (`traffic-gen/`)
- `human_traffic.py`: Playwright script driving Chrome and Firefox against the target site, randomized navigation paths, randomized delays (avoid uniform timing — that itself would be a tell), some real human volunteers browsing manually for a non-synthetic subset.
- `bot_tier1_naive.py`: plain `requests`/`httpx` hitting endpoints directly, no JS execution, no fingerprint spoofing.
- `bot_tier2_evasive.py`: `curl-impersonate` or `tls-client`, configured to mimic a specific Chrome JA3/JA4 string — the expected finding is these tools replicate classical TLS fingerprints but miss PQ key shares and don't speak QUIC.
- `bot_tier3_sophisticated.py`: headless Playwright/Puppeteer — real browser engine, likely passes both classical and new signals; this tier's job is to show your system's honest detection ceiling.
- `session_orchestrator.py`: single entrypoint that runs a batch of sessions across all traffic types, starts/stops the capture sidecar per session, and writes a session manifest (session_id, source_type, tier, timestamp) that later gets joined with extracted features for labeling. This manifest is your ground truth — get its schema right early.

### 4.3 Capture (`capture/`)
- `capture_sidecar.py`: wraps `tshark` (preferred for reliability over raw scapy sniffing) capturing on loopback/relevant interface, filtered to the target site's port, writing one pcap per session keyed by session_id from the orchestrator.
- Store a small sampled subset of pcaps in the repo for reproducibility; keep bulk data out of git (add to `.gitignore`, document regeneration steps instead).

### 4.4 Feature Extraction (`feature-extraction/`)
Canonical feature schema (`feature_schema.py`) — this is the exact table your model trains on:

| Field | Type | Source |
|---|---|---|
| `session_id` | string | orchestrator manifest |
| `ja4_fingerprint` | string (hash) | ja4_extractor.py |
| `ja4_raw_components` | string | ja4_extractor.py (kept for interpretability, not fed raw to model) |
| `tls_version` | categorical | ClientHello |
| `cipher_suite_count` | int | ClientHello |
| `cipher_suite_order_hash` | string | ClientHello |
| `extension_count` | int | ClientHello |
| `supported_groups` | list→multi-hot | ClientHello key_share/supported_groups extension |
| `has_pq_keyshare` | bool | **core new feature** — checks for x25519mlkem768 group ID |
| `alpn_protocols` | list→multi-hot | ClientHello ALPN extension |
| `used_http3` | bool | **core new feature** — did the session actually use QUIC |
| `quic_version` | categorical, nullable | QUIC Initial packet, if present |
| `quic_transport_param_count` | int, nullable | QUIC Initial packet, if present |
| `label` | categorical | orchestrator manifest: human / bot_tier1 / bot_tier2 / bot_tier3 |

Explicit design note: **do not use User-Agent string as a model feature.** It's trivially spoofable and would let the model cheat on your own synthetic data, invalidating the evaluation. Log it for debugging only.

- `ja4_extractor.py`: wraps the open-source JA4 implementation against the ClientHello bytes extracted from each pcap.
- `quic_parser.py`: parses the QUIC Initial packet's crypto frame (contains an embedded TLS ClientHello) using scapy or a QUIC-aware parsing library — extracts transport parameters and confirms QUIC version.
- `pq_detector.py`: parses the `key_share` and `supported_groups` extensions from the ClientHello, checks specifically for the x25519mlkem768 group ID.
- `build_dataset.py`: joins all per-session features with the orchestrator's label manifest into a single labeled table, written to `dataset.parquet`.

### 4.5 ML Pipeline (`ml/`)
- `train_baseline.py`: trains on JA4 + classical TLS/HTTP fields only (no PQ, no QUIC) — this is your control condition.
- `train_enhanced.py`: same model family, full feature set including `has_pq_keyshare`, `used_http3`, QUIC fields — this is your treatment condition.
- Model: gradient boosting (XGBoost or CatBoost), multi-class target (human / tier1 / tier2 / tier3) — report both multi-class metrics and collapsed binary (human vs. any-bot) metrics.
- `evaluate.py`: outputs accuracy, macro-F1, ROC-AUC (one-vs-rest), confusion matrix, and a direct baseline-vs-enhanced delta table — this delta table is the single most important result in your paper.
- `evasion_test.py`: takes the enhanced model, runs an adaptive bot (a modified Tier 3 bot attempting to correctly replicate PQ key shares and force QUIC usage) against it, reports how much detection accuracy survives. Report this honestly — a partial degradation is a legitimate, expected, publishable finding.

### 4.6 Live Detection Service (`detection-service/`)
**Primary architecture (recommended, lower risk):** a standalone reverse proxy that sits in front of Caddy.
1. `proxy.py`: accepts incoming connections, forwards to Caddy after a scoring decision.
2. In parallel, a lightweight passive listener (reusing the capture-sidecar logic) observes the ClientHello/QUIC Initial packet for each new connection on the same interface.
3. `scorer.py`: loads the trained model once at startup, extracts features from the observed handshake in real time (sub-100ms target), returns a score.
4. Decision logic: score above threshold → forward to Caddy normally; below threshold → serve a 403/challenge page, log the block.
5. `api.py` (FastAPI): exposes `/live-feed` (recent scored sessions) and `/stats` (aggregate accuracy/block-rate) for the dashboard to poll or subscribe to via WebSocket.

**Stretch upgrade (only if time permits after core deliverables are solid):** implement scoring as a custom Caddy Go module hooking into the TLS `GetConfigForClient` callback, which exposes `ClientHelloInfo` directly — this would let Caddy itself make the block/allow decision inline, a more elegant single-system story. Treat this as a v2 enhancement, not a Phase 1 dependency — the standalone proxy above is a fully legitimate, fully functional system on its own and should be your primary target.

### 4.7 Dashboard (`dashboard/`)
- React app matching your existing project's visual style.
- Live feed table: session_id, source IP, fingerprint summary, PQ/QUIC flags, score, decision (allowed/blocked), timestamp.
- Charts (Recharts): detection accuracy over time, baseline vs. enhanced comparison bar chart, block-rate by bot tier.
- This is what the panel watches during your live demo — prioritize this being visually clean over feature-complete.

### 4.8 Database (`db/`)
- SQLite, single file, schema covering: `sessions`, `features`, `labels`, `scores`, `live_events`.
- Simple enough to inspect directly with any SQLite browser during development and debugging.

---

## 5. Build Order (follow this sequence)

1. **Week 1:** Target site + Caddy smoke test (Phase 1 from earlier — confirm QUIC + PQ negotiate before anything else)
2. **Weeks 2-4:** Traffic generation scripts (all four types) + capture sidecar + session orchestrator, producing a raw labeled pcap corpus
3. **Weeks 4-5:** Feature extraction pipeline (JA4, QUIC parser, PQ detector) + dataset builder, producing `dataset.parquet`
4. **Weeks 5-6:** ML training, baseline vs. enhanced comparison, full evaluation report
5. **Week 7:** Evasion testing
6. **Weeks 8-9:** Detection service (standalone proxy architecture) + dashboard
7. **Week 9 onward:** integrate everything via `run_all.sh`/`docker-compose`, polish demo flow, write docs

---

## 6. Non-Functional Requirements
- **Latency target for live scoring:** under 200ms end-to-end (feature extraction + inference) — achievable given XGBoost inference is microsecond-scale; the bottleneck will be packet capture timing, budget for this during testing.
- **Testing:** unit tests for feature extraction correctness (known ClientHello byte sequences → expected feature output) and scorer correctness (known feature vector → expected score range); integration test for the full proxy flow.
- **Reproducibility:** `run_all.sh` should bring up the entire stack (target site, detection proxy, dashboard) from a clean checkout in one command — this matters both for your own sanity and for demo-day reliability.
- **Security of the system itself:** the detection service is internet-facing during demos — keep it scoped to localhost/private network for development, and don't expose the SQLite file or model artifacts publicly.

---

## 7. Definition of Done
- [ ] Caddy target site serving with confirmed QUIC + PQ-TLS negotiation
- [ ] All four traffic generator tiers producing distinguishable, labeled sessions
- [ ] Feature extraction pipeline producing the full schema above for every session
- [ ] Baseline vs. enhanced model comparison with a clear, reportable accuracy/F1 delta
- [ ] Evasion test results, honestly reported
- [ ] Live detection proxy correctly scoring and blocking in real time, sub-200ms
- [ ] Dashboard showing live feed + comparison charts
- [ ] One-command startup script
- [ ] Clean commit history, meaningful messages, proper README with setup instructions
- [ ] All of the above wired together for a single continuous live demo, not disconnected pieces
