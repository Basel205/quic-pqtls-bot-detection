# Consistency-Aware Bot Detection over Next-Generation Network Protocols

This repository evaluates two things over the same lab-generated traffic:

1. **Presence-based detection** (Basel's original contribution) — does a connection show new
   protocol signals (post-quantum TLS key exchange, QUIC/HTTP-3) real browsers have but most bot
   tooling doesn't yet?
2. **Consistency-based detection** (the newer research direction) — does a connection's protocol
   attributes actually *belong together*, the way they would on a real device, rather than just
   checking whether individual signals are present? This is the project's core novel claim,
   borrowed from browser-fingerprint research (FP-Inconsistent, ACM IMC 2025) and applied here,
   to our knowledge for the first time, at the network-protocol layer.

**This file is the setup guide and a quick status snapshot. [`CLAUDE.md`](CLAUDE.md) is the
authoritative, detailed log of every decision, bug, and result — read that before changing
anything or assuming a claim below.**

---

## Current status (updated 2026-09-12) — what's done, what isn't

### Done and validated
- **Full lab infrastructure** (target site with Caddy/QUIC/PQ-TLS, 4-tier bot traffic generator
  + a since-added **Tier 4 adaptive bot**, session orchestrator with repeat-visit
  (`client_identity_id`) grouping, JA4/JA4H + PQ + QUIC feature extraction). Six real bugs found
  and fixed along the way (encoding crashes, a scapy side-effect crash, a SQLite schema mismatch, a
  QUIC-decryption stub, structurally-broken timing features, and a tshark capture race condition
  that would have silently corrupted up to half the main dataset) — see `CLAUDE.md`'s Current
  Status for each one.
- **Main dataset**: `feature-extraction/dataset.parquet` — 1,600 sessions (500 human / 400 tier1 /
  400 tier2 / 300 tier3), 28 features, zero NaNs, zero duplicates, class balance verified exact.
- **Tier 4 (adaptive evasion bot)**: 200 sessions generated (real headless Chrome + human-mimicking
  timing + a randomized full/degraded QUIC backend profile per session — see `CLAUDE.md` for why).
- **Consistency-scoring layer** (`consistency-layer/`, new — kept separate from Basel's files):
  spatial (D1) and temporal (D2) inconsistency scorers, both built, both scored against all 1,600
  + 200 sessions.
- **External reference dataset integrated** (see "Existing dataset used?" below) — this directly
  answers earlier panel feedback not to rely only on our own lab-generated data.
- **All planned core experiments trained**: A (classical baseline), B (presence-enhanced),
  D1 (+ spatial score), D2 (+ spatial & temporal score) — plus two follow-up ablation arms
  (`Ablation_spatial_only`, `Ablation_full_consistency`) run after the evasion test raised a
  question the original ablation table didn't anticipate.
- **The required evasion test (Tier 4 vs. every model) — run, and the result is fully diagnosed**,
  not just reported. Headline: D1/D2 currently give **zero** additional evasion resistance over B
  (97.0% evasion rate, identical predictions to B). This was *not* accepted at face value — traced
  to a training-data coverage gap (no training example combines "protocol-realistic bot" with
  "one inconsistent dimension"), not a broken idea. Full mechanism, numbers, and the ablation
  follow-up are in `CLAUDE.md`.

### Not done yet
- `ml/evaluate.py` and `ml/feature_importance.py` (SHAP) — both still empty stub files.
- The other 3 planned ablation arms (PQ-only, QUIC-only, Timing-only) — only the 2 that the
  evasion-test finding specifically motivated were run.
- **Phase 6 (live proxy + dashboard) and the paper draft — not started, on purpose.** The
  project's own phase-gating rule blocks Phase 6 until the evasion-resistance test is complete;
  it now is, but see the open decision below before treating that gate as fully cleared.
- **One open methodology decision, needs Basel's input before proceeding**: whether to give a
  future training run actual exposure to Tier-4-like "consistent except one dimension" examples
  (e.g. a held-out split *within* Tier 4 itself), rather than treating all 200 Tier-4 sessions as
  pure held-out evasion-test data as done so far. This changes what "evasion test" means for the
  paper, so it's flagged rather than decided unilaterally — see the end of `CLAUDE.md`'s
  Tier-4/ablation section.

### Existing dataset used? — yes, confirmed and wired in
Per earlier panel feedback ("don't only train on data we generated ourselves"), this project
integrates a real, independently-collected external dataset: **40 genuine `Human` TLS-fingerprint
rows** from the public artifact behind *"On the Internet, Nobody Knows You're an LLM Bot"*
(arXiv:2606.30119, June 2026) — passively captured via tshark from real browsers, including real
observations of the same `0x11EC` PQ codepoint this project is built around. A trimmed copy lives
at `consistency-layer/external-data/llm_agent_study_tls_fingerprints.csv` (full provenance and
caveats in that directory's `README.md`). `consistency-layer/external_reference.py` normalizes it
into this project's own feature vocabulary, and `consistency-layer/expected_combinations.py`
combines it with our own 500 lab human sessions (540 total, tagged `source=lab` vs.
`source=external_llm_agent_study` so the mix stays auditable) to build the table D1's spatial
scorer is checked against. It is **not** merged into the A/B/D1/D2 training set itself — the
external automated-tool rows use a different bot-tier taxonomy that isn't directly comparable to
`bot_t1`–`bot_t4`, so it's kept as an external validation/reference set, not additional labeled
training rows.

A separate, better-fitting-on-paper source (JA4+ Database, ja4db.com) was investigated and
**not** used — its API requires third-party account signup, which wasn't something that could be
done on the team's behalf. Documented as a dead end in `CLAUDE.md` in case someone signs up later.

---

## 🚀 Setup Guide (for Basel, or anyone picking this repo up fresh)

Built for **Windows** (Wireshark/Npcap's loopback capture is Windows-specific). Follow these
steps in order.

### 1. Prerequisites
- **Python 3.11+** (this was developed against 3.14.3 — some pinned versions in
  `requirements.txt` have no prebuilt wheels for 3.14 yet; see the note under step 3)
- **Node.js** (v18+)
- **Caddy** (on PATH — `choco install caddy` works)
- **Wireshark / Npcap** — during Npcap install, check **"Support loopback traffic
  (`\Device\NPF_Loopback`)"**. If missed, reinstall Npcap.

### 2. Clone
```bash
git clone https://github.com/Basel205/quic-pqtls-bot-detection.git
cd quic-pqtls-bot-detection
```

### 3. Python environment
```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
playwright install chromium
```
**If you're on Python 3.14+ and some packages fail to install** (no prebuilt wheel, needs a C++
build toolchain): `pandas`, `pyarrow`, and `playwright` were the ones that hit this. Installing
them unpinned (`pip install pandas pyarrow playwright` without version pins) worked cleanly on
this machine — a local workaround, not a change to `requirements.txt` itself. `aioquic==1.2.0`
and `xgboost==2.1.0` (both pinned, both needed — see below) installed cleanly as-is.
`catboost`/`shap`/`mlflow` are in `requirements.txt` for later work (CatBoost comparison, SHAP
feature importance) but aren't installed yet on this machine since nothing uses them yet.

⚠️ **Unresolved, pre-existing**: `requests==2.32.0` (the exact pin in `requirements.txt`) is a
**yanked PyPI release** — pip will warn it conflicts with the CVE-2024-35195 mitigation. Should
probably be re-pinned to a newer patch version; not yet decided who/when.

### 4. Start the target site
Terminal 1:
```bash
cd target-site
npm install
node server.js
```
Terminal 2:
```bash
cd target-site
caddy run --config Caddyfile
```
⚠️ **Gotcha found this project (cost a debugging session)**: after any long idle gap, Caddy's
local leaf certificate can expire and get stuck in a broken renewal loop — it'll keep serving
`https://localhost` successfully (curl/browser automation both bypass cert errors), but
Chromium's QUIC/Alt-Svc upgrade path validates the cert independently and will **silently never
attempt QUIC at all** if it's expired, with no visible error anywhere. If a data-generation run
suddenly shows `used_http3=0` for sessions that should have QUIC, check the served cert's
`notAfter` first (`openssl s_client -connect localhost:443 | openssl x509 -noout -dates`) before
assuming it's a code bug. Fix: stop Caddy, delete
`%APPDATA%\Caddy\certificates\local\localhost\localhost.json` if present, restart Caddy.

### 5. Verify the capture interface
`tshark.exe` should be at `C:\Program Files\Wireshark\tshark.exe` (or update `TSHARK_BIN` in
`traffic-gen/tg_config.py`). Run `tshark -D` and confirm `\Device\NPF_Loopback` is listed;
`traffic-gen/tg_config.py`'s `TSHARK_INTERFACE` should match it.

### 6. Smoke test
```bash
python traffic-gen/session_orchestrator.py --mini
```
Expect `human`, `bot_t1`, `bot_t2`, `bot_t3` sessions to run and produce non-empty pcaps in
`capture/pcap_store/`. `EMPTY PCAP` errors usually mean tshark needs Administrator, or loopback
Npcap support wasn't installed.

### 7. Reproducing the actual results (no new capture needed — all pcaps/artifacts are already
   generated and gitignored, but the derived files below are checked in and small)
```bash
# Consistency scores (rebuilds from dataset.parquet + external reference data)
python consistency-layer/expected_combinations.py
python consistency-layer/spatial_score.py
python consistency-layer/temporal_score.py

# Train all core + ablation experiments
python ml/train_baseline.py            # A
python ml/train_enhanced.py            # B
python consistency-layer/train_d1_d2.py   # D1, D2
python ml/train_utils.py Ablation_spatial_only
python ml/train_utils.py Ablation_full_consistency

# Run the Tier-4 evasion test against all six trained models
python ml/evasion_test.py
```
Note: `feature-extraction/dataset.parquet`, `ml/tier4_dataset.parquet`, `ml/model_registry/*.joblib`,
and `capture/pcap_store/*.pcap` are all **gitignored** (large/regeneratable) but already present
in this working copy — a fresh clone will need to either regenerate them (full generation run
takes a couple of hours) or receive them out-of-band. Worth a quick conversation with whoever's
picking this up about how to hand those specific files over, since git isn't carrying them.

---

## 📂 Project Structure
- `target-site/` — Caddy proxy + Node.js dummy app.
- `traffic-gen/` — bot scripts (`bot_tier1_naive`, `bot_tier2_evasive`, `bot_tier3_sophisticated`,
  `bot_tier4_adaptive`, `human_traffic`) + `session_orchestrator.py` + `session_manifest.csv`
  (ground-truth labels + `client_identity_id` repeat-visit grouping).
- `capture/` — `capture_sidecar.py` wrapper + `.pcap` outputs (gitignored).
- `feature-extraction/` — PQ/QUIC/timing/JA4/JA4H extractors, `feature_schema.py` (single source
  of truth for the feature list), `build_dataset.py`, `dataset.parquet` (gitignored).
- `consistency-layer/` — **new this phase, kept separate from Basel's files on purpose**: the
  spatial (D1) and temporal (D2) inconsistency scorers, the expected-combination table builder,
  external reference dataset integration, and D1/D2 training entry point.
- `ml/` — experiment config (`ml_config.py`), shared train/eval logic (`train_utils.py`), the A/B
  entry-point scripts, the Tier-4 evasion test, trained models (`model_registry/`, gitignored),
  and results (`results/*.json`, small, checked in).
- `db/` — SQLite schema + init script.

## ⏭️ Next steps for the team
1. **Decide the open methodology question above** (train/held-out split within Tier 4) before
   running more experiments on top of the evasion-test finding.
2. Build `ml/feature_importance.py` (SHAP on the D2 model) and `ml/evaluate.py` — planned, not
   started.
3. Once 1–2 are resolved, Phase 6 (live proxy + dashboard) and the paper draft are next per the
   phase-gating rule.
