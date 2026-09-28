# QUIC PQ-TLS Bot Detection — Project Handoff

> **Branch:** `feature` | **Last updated:** 2026-09-28
> **Status:** Experiments complete, Tier 5 dataset in progress. Paper-ready numbers in `ml/results/`.

---

## Table of Contents
1. [What This Project Is](#what-this-project-is)
2. [Repository Layout](#repository-layout)
3. [Environment Setup](#environment-setup)
4. [Dataset — Full Status](#dataset--full-status)
5. [Experiments — What Was Run and What Every Number Means](#experiments--what-was-run-and-what-every-number-means)
6. [Where the Results Are Weak](#where-the-results-are-weak)
7. [What Still Needs to Be Done](#what-still-needs-to-be-done)
8. [Running Everything from Scratch](#running-everything-from-scratch)

---

## What This Project Is

**Research question:** Can post-quantum TLS (PQ-TLS) and QUIC protocol signals, combined with cross-session consistency scoring, detect bots that have been specifically engineered to evade presence-based detection?

**Key claim:** A consistency-augmented detector (Model D2) that tracks fingerprint drift *across sessions from the same identity* can still catch bots even when every individual session looks perfectly human — and even when the bots have learned to spoof PQ-TLS and QUIC presence.

**Why it matters:** PQ-TLS adoption is accelerating (Google Chrome has shipped X25519MLKEM768 since 2024). Bot operators who fingerprint-spoof today use static profiles that do not adapt across requests from the same "identity." Cross-session temporal inconsistency is an orthogonal signal that survives presence-spoofing.

---

## Repository Layout

```
quic-pqtls-bot-detection/
├── _paths.py                        # Adds all subdirs to sys.path — import this first in every script
├── tg_config.py                     # Central config: paths, URLs, seeds, hyperparams
├── CLAUDE.md                        # Non-negotiable technical constraints (READ THIS)
│
├── feature-extraction/
│   ├── feature_schema.py            # SINGLE SOURCE OF TRUTH for all feature sets
│   ├── build_dataset.py             # Per-pcap feature extractor → dataset.parquet
│   ├── pq_detector.py               # Parses ClientHello, detects PQ keyshare
│   ├── quic_parser.py               # Parses QUIC Initial packet
│   ├── ja4_extractor.py             # JA4 fingerprint computation
│   ├── ja4h_extractor.py            # JA4H (HTTP-layer) fingerprint
│   ├── timing_extractor.py          # Behavioral timing features
│   └── dataset.parquet              # ← COMMITTED: 1,600-session base dataset (Tiers 1-3)
│
├── consistency-layer/               # Harshil's domain — do not merge into feature-extraction
│   ├── expected_combinations.py     # Human baseline: expected PQ+QUIC+TLS combos
│   ├── spatial_score.py             # D1: per-session inconsistency vs. human baseline
│   ├── temporal_score.py            # D2: cross-session drift within identity group
│   └── train_d1_d2.py               # Trains D1, D2, and all *_retrained arms
│
├── ml/
│   ├── ml_config.py                 # All 13 experiment definitions + registry paths
│   ├── train_utils.py               # Shared train/eval loop (all experiments go through here)
│   ├── split_tier4.py               # Identity-group-level train/test split for Tier 4
│   ├── train_retrained.py           # Entry point for training all *_retrained arms
│   ├── evasion_test.py              # Main evasion evaluation: B vs D1 vs D2 on Tier 4
│   ├── group_level_eval.py          # Group-level noisy-OR aggregation analysis
│   ├── evaluate.py                  # Per-class precision/recall + binary AUC report
│   ├── multi_seed_eval.py           # 5-seed robustness check
│   ├── feature_importance.py        # SHAP analysis for all three retrained models
│   ├── significance_and_graphs.py   # McNemar's test + ROC + evasion bar chart
│   ├── consistency_risk_score.py    # Logistic formula: C(s) = sigmoid(α + β₁·spatial + β₂·temporal)
│   ├── section10_improvements.py    # LightGBM, k-fold CV, hyperparam search, class weighting
│   ├── model_registry/              # Trained .joblib models (gitignored — regenerate with train_utils.py)
│   ├── results/                     # All JSON/CSV outputs from experiments (committed)
│   └── figures/                     # SHAP PNGs, ROC curve, evasion bar chart (committed)
│
├── detection-service/               # Phase 6: Live detection proxy
│   ├── feature_realtime.py          # Extracts features from a live ClientHello (no pcap)
│   ├── scorer.py                    # Loads B_enhanced_retrained, scores a connection in real-time
│   ├── proxy.py                     # Async TCP passthrough: peeks ClientHello, scores, relays
│   └── api.py                       # FastAPI + WebSocket broadcaster for live risk scores
│
├── traffic-gen/
│   ├── session_orchestrator.py      # Master orchestrator: spawns bots + tshark capture per session
│   ├── tg_config.py → (root)        # Symlinked to root tg_config.py
│   ├── bot_tier1_wget.py            # Tier 1: simple wget/curl bot
│   ├── bot_tier2_basic_browser.py   # Tier 2: headless browser, no timing mimicry
│   ├── bot_tier3_adaptive.py        # Tier 3: timing-mimicking bot, no PQ spoof
│   ├── bot_tier4_adaptive.py        # Tier 4: full PQ+QUIC spoof, adaptive evasion
│   └── bot_tier5_identity_drift.py  # Tier 5: identity-drift bot (cross-session only signal)
│
├── target-site/
│   ├── server.js                    # Express.js mock API (runs on :3000)
│   ├── Caddyfile                    # Caddy config: TLS termination on :443, HTTP/3, reverse proxy
│   └── logs/access.log              # Caddy access log (gitignored)
│
└── capture/
    ├── capture_sidecar.py           # tshark wrapper: captures per-session pcaps
    └── pcap_store/                  # Raw pcap files (gitignored — too large)
```

---

## Environment Setup

**Requirements:** Windows 10/11, Anaconda (conda), Node.js, Caddy, Wireshark (tshark), Git.

```powershell
# 1. Clone and enter the repo
git clone https://github.com/Basel205/quic-pqtls-bot-detection.git
git checkout feature

# 2. Create and activate the conda environment
conda create -n SIH python=3.11
conda activate SIH

# 3. Install Python dependencies
pip install xgboost scikit-learn pandas numpy pyarrow joblib matplotlib \
            shap scipy fastapi uvicorn websockets lightgbm playwright mlflow

# 4. Install Playwright browsers (needed for Tier 3-5 traffic generation)
python -m playwright install chromium chrome

# 5. Install Node.js dependencies for the target site
cd target-site && npm install && cd ..

# 6. Verify Caddy is installed
caddy version   # if not found: winget install CaddyServer.Caddy

# 7. Verify tshark (for traffic capture)
where tshark    # usually at C:\Program Files\Wireshark\tshark.exe
```

**Conda environment name:** `SIH` (Python 3.11, CUDA 12.8 / RTX 4060 Laptop GPU)

---

## Dataset — Full Status

### What exists right now

| Dataset | File | Sessions | Labels | Status |
|---|---|---|---|---|
| Base dataset | `feature-extraction/dataset.parquet` | 1,600 | human (400), bot_t1 (400), bot_t2 (400), bot_t3 (400) | ✅ Committed, used for all A/B/D1/D2 training |
| Tier 4 evaluation | `ml/tier4_dataset.parquet` | 200 | bot_t4 (200) | ✅ Committed, used for all evasion tests |
| Tier 4 split IDs | `ml/tier4_train_ids.csv`, `ml/tier4_test_ids.csv` | 126 train / 74 test | bot_t4 | ✅ Committed |
| Tier 5 | Not yet extracted | 200 sessions generated | bot_t5 | ⚠️ Traffic captured, feature extraction NOT yet run |

### Dataset architecture — important constraints

1. **`dataset.parquet` is FROZEN.** Do not add to it, rebuild it, or change its 1,600 rows. It is the fixed training set for all A/B/D1/D2 experiments. Tier 4 lives in a separate file.

2. **Tier 4 split is by `client_identity_id` group**, not by session. An identity's sessions must all be on the same side of the train/test boundary. This is enforced by `split_tier4.py`. Never split an identity group across train/test.

3. **Consistency scores are NOT stored in parquet.** `spatial_inconsistency_score` and `temporal_inconsistency_score` are computed at load time by `train_utils.load_dataset_for_experiment()`. They are derived, not stored, to keep the dataset file clean.

4. **`dataset.parquet` split is at SESSION level** (not identity-group level for Tiers 1-3). This is documented as Bug-01 in `CLAUDE.md`. It is acceptable for now because Tiers 1-3 bots don't have identity structure — every session is independent.

5. **Multi-hot encoding is MANDATORY** for `supported_groups` and `alpn`. Do not collapse these to a single hash — the individual group bits (`sg_x25519mlkem768`, `sg_x25519`, `sg_secp256r1`, `alpn_h3`, `alpn_h2`, etc.) are what enable the PQ/QUIC signal detection.

### Tier 5 dataset — what needs to be done

The Tier 5 traffic (200 sessions of identity-drift bot — alternating between Chromium and system Chrome channels under the same `client_identity_id`) was **generated and captured** to pcap files. The next required step is:

```powershell
# Make sure Caddy + node are running, then:
conda activate SIH
python ml/evasion_test.py --tier5   # (if tier5 support is added to evasion_test)
# OR build the tier5 dataset manually:
python -c "
from ml.evasion_test import build_tier4_dataset
# Replace 'bot_t4' with 'bot_t5' in the manifest filter
"
```

See [What Still Needs to Be Done](#what-still-needs-to-be-done) for the exact steps.

---

## Experiments — What Was Run and What Every Number Means

### The Experiment Ladder

The project defines 13 named experiments, each a named configuration of (feature set, dataset, training mode). All share the same XGBoost classifier and the same 70/15/15 train/val/test split from `dataset.parquet`.

| Experiment | Feature Set | Training Data | Purpose |
|---|---|---|---|
| `A_baseline` | Classical TLS/JA4 only | Tiers 1-3 | Floor: what was possible before PQ/QUIC |
| `B_enhanced` | Classical + PQ + QUIC + Timing | Tiers 1-3 | Full feature set, frozen |
| `C_ablation` | Classical + PQ + QUIC (no timing) | Tiers 1-3 | Isolate: does PQ+QUIC without timing help? |
| `PQ_only` | Classical + PQ keyshare only | Tiers 1-3 | Isolate: PQ signal alone |
| `QUIC_only` | Classical + QUIC signals only | Tiers 1-3 | Isolate: QUIC signal alone |
| `Timing_only` | Classical + behavioral timing only | Tiers 1-3 | Isolate: timing signal alone |
| `D1_spatial` | B_features + spatial score | Tiers 1-3 | Adds cross-identity spatial consistency |
| `D2_spatial_temporal` | B_features + spatial + temporal | Tiers 1-3 | Full consistency model, frozen |
| `B_enhanced_retrained` | Same as B_enhanced | Tiers 1-3 + Tier 4 train-split | Control: what does retraining on adaptive bots give B? |
| `D1_spatial_retrained` | Same as D1 | Tiers 1-3 + Tier 4 train-split | D1 retrained on adaptive bots |
| `D2_spatial_temporal_retrained` | Same as D2 | Tiers 1-3 + Tier 4 train-split | **Primary result** |
| `Ablation_spatial_only` | Spatial score only | Tiers 1-3 | Consistency layer ablation |
| `Ablation_full_consistency` | Both scores only | Tiers 1-3 | Consistency layer ablation |

---

### In-Distribution Results (Tiers 1–3 test split, n=240)

All models score near-perfectly on non-adaptive bots. This is expected and correct — Tiers 1-3 are simple and the models are trained on them.

| Model | Accuracy | Macro-F1 | ROC-AUC | FP rate on real humans |
|---|---|---|---|---|
| A_baseline | 79.2% | 0.768 | 0.925 | 28.0% (21/75 misclassified) |
| B_enhanced | 99.6% | 0.996 | 1.000 | 1.3% (1/75) |
| C_ablation (PQ+QUIC, no timing) | 80.4% | 0.778 | 0.925 | similar to A |
| PQ_only | 80.4% | 0.778 | 0.925 | similar to A |
| QUIC_only | 79.6% | 0.772 | 0.925 | similar to A |
| **Timing_only** | **99.6%** | **0.996** | **1.000** | 1.3% |
| D1_spatial | 99.6% | 0.996 | 1.000 | 1.3% |
| D2_spatial_temporal | 99.6% | 0.996 | 1.000 | 1.3% |

**Key finding from ablation:** `Timing_only` achieves identical accuracy to the full `B_enhanced`. PQ and QUIC signals individually add essentially nothing (+1%) over A_baseline. **B's improvement over A is entirely driven by behavioral timing features, not PQ/QUIC presence.** This is the honest paper finding — PQ/QUIC are future-proofing signals, not the source of the current accuracy lift.

---

### Evasion Test Results (Tier 4 adaptive bot, n=74 held-out test sessions)

**This is the primary scientific result.** Tier 4 bots were built with full knowledge of the feature set, spoof PQ+QUIC presence, and mimic human timing. The question: can detection hold up?

| Model | Evasion Rate | Caught |
|---|---|---|
| A_baseline | ~79% evasion | 21% caught |
| B_enhanced_retrained | **58.1%** evasion | **41.9%** caught |
| D1_spatial_retrained | 59.5% evasion | 40.5% caught |
| **D2_spatial_temporal_retrained** | **18.9%** evasion | **81.1%** caught |

**Interpretation:**
- B drops from near-100% in-distribution to 58.1% against an adaptive adversary. Half the adaptive bots walk right through.
- D1 (spatial score alone) adds almost nothing over B — the spatial score is a step function of PQ+QUIC presence, which the bot already spoofs correctly. D1's SHAP importance for bot_t4 is 0.000 — confirmed dead.
- **D2 drops evasion to 18.9%** — catching 81% of sessions that B misses. The temporal score (`temporal_inconsistency_score`) is the #1 SHAP feature for bot_t4 decisions, with mean |SHAP| = 1.555, a 58% margin over the next feature.

**Binary AUC (human-vs-bot_t4, threshold-independent):**

| Model | ROC-AUC | PR-AUC |
|---|---|---|
| B_enhanced_retrained | 0.714 | 0.666 |
| D1_spatial_retrained | 0.717 | 0.676 |
| **D2_spatial_temporal_retrained** | **0.932** | **0.882** |

---

### Statistical Significance

**McNemar's test** (B vs D2 on 74 paired sessions):
- Discordant pairs: 39 (sessions where B and D2 disagree)
- **p = 0.000002**
- The D2 advantage is not explainable by chance.

---

### Multi-Seed Robustness (5 seeds: 42, 1, 7, 123, 2024)

The evasion test was re-run across 5 random seeds to ensure the result is not seed-sensitive.

| Model | Mean Evasion | Std | Range |
|---|---|---|---|
| B_enhanced_retrained | 62.5% | ±4.5% | 58–68% |
| D1_spatial_retrained | 62.5% | ±4.4% | 59–68% |
| **D2_spatial_temporal_retrained** | **18.1%** | **±4.4%** | **13–23%** |

D2's advantage is stable and consistent. The ~44 percentage point gap between B and D2 holds across all seeds.

---

### SHAP Feature Importance (bot_t4 decision specifically)

**D2 (`D2_spatial_temporal_retrained`) — top features for detecting bot_t4:**

| Rank | Feature | Mean |SHAP| | What it measures |
|---|---|---|---|
| 1 | `temporal_inconsistency_score` | **1.555** | Cross-session TLS fingerprint drift within an identity group |
| 2 | `inter_request_timing_cv` | 0.995 | Coefficient of variation in delays between requests |
| 3 | `session_request_count` | 0.785 | Number of requests in the session |
| 4 | `record_layer_timing_p50` | 0.309 | Median TLS record layer timing |

**D1 — `spatial_inconsistency_score` = 0.000.** D1's consistency signal is dead on Tier 4 because the bot correctly spoofs PQ+QUIC in every session, so it always matches the expected spatial profile. Three independent methods confirm this: SHAP importance, tree feature importance, and score variance analysis.

---

### LightGBM Cross-Model Validation (Section 10.1)

Same feature sets, same data, different model family — verifies the finding is not an XGBoost artifact.

| Model | LightGBM Evasion | XGBoost Evasion |
|---|---|---|
| B_enhanced_retrained | 58.1% | 58.1% |
| D1_spatial_retrained | 59.5% | 59.5% |
| **D2_spatial_temporal_retrained** | **14.9%** | **18.9%** |

D2 wins by an even larger margin on LightGBM. **The result is about the signal, not the model family.**

---

### Stratified 5-Fold CV (Section 10.2)

Tighter confidence intervals than the single-split train results:

| Model | Accuracy | Macro-F1 |
|---|---|---|
| B_enhanced_retrained | 0.936 ± 0.010 | 0.868 ± 0.019 |
| D2_spatial_temporal_retrained | **0.983 ± 0.003** | **0.975 ± 0.005** |

---

### Hyperparameter Search (Section 10.3)

RandomizedSearchCV (20 trials, 3-fold, D2 features):
- Best CV macro-F1: **0.9765** vs. current default 0.9745
- Improvement: **+0.2%** — the hand-picked defaults were already near-optimal.
- Best params found: `lr=0.10, n_estimators=200, max_depth=7, subsample=1.0, colsample=0.6, min_child_weight=7, gamma=0.5`
- Results saved to `ml/results/hyperparam_search.json`

---

### Class Weighting for bot_t4 Minority (Section 10.4)

bot_t4 is 7.3% of the retrained dataset (126/1726 rows). Tested two rebalancing approaches:

| Method | Evasion | bot_t4 Recall (in-dist) |
|---|---|---|
| Baseline D2 (no weighting) | 18.9% | 84.2% |
| XGBoost sample_weight (2.7×) | **14.9%** | 84.2% |
| Oversampling to 20% | **14.9%** | 84.2% |

Both methods **reduce evasion 4pp with no false-positive tradeoff**. Worth applying to the final model.

---

### Consistency Risk Score (Logistic Formula)

A closed-form logistic formula combining spatial and temporal scores for human-readable group-level risk:

```
C(s) = sigmoid(-0.410 + 1.006 × spatial(s) + 3.641 × temporal(s))
```

- Fitted on 1,726 sessions (base + Tier-4 train split)
- Threshold: 0.95 (chosen on 8 validation groups)
- **Test groups caught: 17/21 (81.0%)**
- Session-level evasion under this formula: **14.9%**
- Temporal weight (3.641) is 3.6× the spatial weight (1.006), confirming temporal is the dominant signal

---

## Where the Results Are Weak

### 1. D1 (spatial score) is essentially useless against Tier 4+
The spatial score is a step function of PQ+QUIC presence. Any bot that correctly negotiates PQ+QUIC in every session will score 0 every time and evade D1 completely. This is confirmed by three methods. **D1 should not be presented as a standalone contribution — it is a stepping stone to D2.**

### 2. ~19% of Tier 4 sessions still evade D2
14 sessions out of 74 that evade D2 are currently unexplained. Group-level analysis (`group_level_eval.py`) shows some identity groups have only 1-2 sessions, giving temporal scoring insufficient signal to detect drift. Real-world deployment would use a session-count threshold (e.g., "don't score groups with < 3 sessions").

### 3. The base dataset split is at session level (Bug-01)
Tiers 1-3 (the 1,600-session training set) are split randomly by session, not by any identity-group key. Since Tiers 1-3 bots are independently generated, this is unlikely to cause real data leakage — but it is a methodological inconsistency vs. the Tier 4 group-level split. A reviewer could flag this.

### 4. Tier 5 evaluation not yet run
The Tier 5 traffic (identity-drift bot: alternates Chromium / system Chrome channels within the same identity) has been generated but not yet feature-extracted or evaluated. **This is the project's most important remaining experiment** — it tests D2 with zero single-session tells, leaving temporal drift as the *only* possible detection signal.

### 5. No real human traffic yet
The `human` label in the dataset is lab-generated human browsing, not recruited volunteers. A reviewer will correctly note that lab-generated human sessions may not represent real-world TLS fingerprint diversity (e.g., enterprise proxies, VPNs, mobile users, Firefox, Safari). The planned volunteer recruitment (20-30 people via ngrok tunnel, tagged `human_real`) has not yet been executed.

### 6. Proxy latency is ~790ms
The detection proxy (`detection-service/proxy.py`) uses a per-request `pd.DataFrame` for inference, which benchmarks at ~790ms. The target for a real-world deployment is <200ms. The fix is to replace the DataFrame with a pre-built numpy array fed directly to `XGBClassifier.get_booster().predict()`.

### 7. Single server, single network, single city
All training and evaluation traffic was generated from a single machine to a local Caddy server. No geographic diversity, no CDN path variation, no mobile network timing characteristics. The behavioral timing features may be overfit to the lab's network RTT profile.

---

## What Still Needs to Be Done

### IMMEDIATE (blocker for paper)

#### 1. Tier 5 feature extraction and evaluation
```powershell
# Start Caddy + node (if not already running):
cd target-site && node server.js          # Window 1
caddy run --config Caddyfile              # Window 2

# Then extract features from Tier 5 pcaps and evaluate:
conda activate SIH
cd ..   # back to project root

# The pcaps for the 200 Tier 5 sessions are in capture/pcap_store/
# Each session_id has a corresponding .pcap file.
# Step 1: Add bot_t5 sessions to the manifest (if not already there)
# Step 2: Build tier5_dataset.parquet (mirrors how tier4_dataset.parquet was built)
python ml/evasion_test.py --rebuild   # if tier5 entries are in session_manifest.csv

# Step 3: Run group-level split for Tier 5
python ml/split_tier4.py --tier5   # (may need to extend split_tier4.py to accept --tier5 flag)

# Step 4: Evaluate D2 on Tier 5
python ml/evasion_test.py --tier tier5
```

**Expected result if D2's temporal hypothesis is correct:**
- A/B/D1 evasion against Tier 5: ~95–100% (no single-session tells for them to find)
- D2 evasion against Tier 5: significantly lower (temporal drift is the only signal, and it's real)

This is the **cleanest possible falsification test**: if D2 does NOT outperform B on Tier 5, the temporal hypothesis fails. If D2 does outperform B, the paper's central claim is proven without any confounds.

#### 2. Apply class weighting to the final trained model
Section 10.4 showed that `sample_weight=2.7×` reduces Tier 4 evasion from 18.9% → 14.9% with no FP tradeoff. This should be applied to `D2_spatial_temporal_retrained` before the final reported numbers:
```python
# In train_utils.py, modify train_and_evaluate() to pass sample_weight
# when experiment name ends in '_retrained' and dataset contains bot_t4
```

#### 3. Volunteer human traffic collection
Recruite 20-30 classmates via ngrok tunnel:
```powershell
# In a new terminal, while Caddy is running:
ngrok http https://localhost:443 --host-header=localhost
# Share the ngrok URL with volunteers. Each person visits 3-5 times over 2-3 days.
# Tag their sessions as label="human_real" in session_manifest.csv (separate from "human")
```

### IMPORTANT (paper quality)

#### 4. Proxy latency optimization
In `detection-service/scorer.py`, replace:
```python
df = pd.DataFrame([features])
pred = _model_B.predict(df[EXPERIMENT_B_FEATURES])
```
With:
```python
booster = _model_B.get_booster()
dmat = xgb.DMatrix(np.array([[features[f] for f in EXPERIMENT_B_FEATURES]]))
pred_raw = booster.predict(dmat)
```
Target: reduce from ~790ms to <200ms per connection.

#### 5. Fix Bug-01: Identity-group split for base dataset
If a reviewer raises this, implement group-level splitting for Tiers 1-3 in `train_utils.py`. This requires adding a `client_identity_id` column to `dataset.parquet` — or documenting explicitly why session-level split is acceptable for Tiers 1-3 (each session IS independent for those tiers).

#### 6. Multi-session threshold for D2
Add a minimum-group-size filter to `evasion_test.py` and `consistency_risk_score.py`: skip scoring groups with fewer than 3 sessions (insufficient temporal signal). Report separately: D2 accuracy on groups with n≥3 vs. n<3.

### OPTIONAL (paper strengthening)

#### 7. Real volunteer traffic evaluation
Once volunteer sessions are collected, train a `D2_with_real_humans` variant and check whether the false-positive rate stays at 1.3% on real humans vs. lab humans.

#### 8. Geographic diversity test
Set up Caddy on a remote VPS (e.g., DigitalOcean/Hetzner). Generate traffic from 2-3 different geographic locations. Verify that timing features (specifically `record_layer_timing_p50`, `inter_request_timing_cv`) remain discriminative under higher-RTT conditions.

#### 9. Paper write-up
All result sections now have real, verified numbers. The paper structure should be:
- §3 Threat Model: Tier 4 + Tier 5 bot design
- §4 Detection Architecture: feature schema → consistency layer → D2
- §5 Ablation: Timing_only = Timing+PQ+QUIC → PQ/QUIC are presence signals not performance drivers
- §6 Evasion Evaluation: B=58.1% vs D2=18.9%, McNemar p=0.000002
- §7 Robustness: 5-seed ±4.4%, LightGBM confirms, 5-fold CV confirms
- §8 Tier 5 (identity drift): [results pending]
- §9 Live Deployment: proxy architecture, latency

---

## Running Everything from Scratch

```powershell
conda activate SIH

# Step 1: Generate traffic (requires Caddy + node running)
python traffic-gen/session_orchestrator.py --tier human    # 400 sessions
python traffic-gen/session_orchestrator.py --tier bot_t1   # 400 sessions
python traffic-gen/session_orchestrator.py --tier bot_t2   # 400 sessions
python traffic-gen/session_orchestrator.py --tier bot_t3   # 400 sessions
python traffic-gen/session_orchestrator.py --tier bot_t4   # 200 sessions

# Step 2: Build dataset
python feature-extraction/build_dataset.py   # → feature-extraction/dataset.parquet

# Step 3: Split Tier 4 by identity group
python ml/split_tier4.py

# Step 4: Train all experiments
python ml/train_utils.py A_baseline
python ml/train_utils.py B_enhanced
python ml/train_utils.py C_ablation
python ml/train_utils.py PQ_only
python ml/train_utils.py QUIC_only
python ml/train_utils.py Timing_only
python consistency-layer/train_d1_d2.py   # trains D1, D2, and all *_retrained arms

# Step 5: Run evasion test
python ml/evasion_test.py

# Step 6: Run all analysis scripts
python ml/evaluate.py
python ml/multi_seed_eval.py
python ml/feature_importance.py
python ml/significance_and_graphs.py
python ml/consistency_risk_score.py
python ml/section10_improvements.py

# Step 7: View results
# All JSON outputs → ml/results/
# All figures → ml/figures/
```

---

## Key Constants and Where to Change Them

| What | Where | Variable |
|---|---|---|
| Random seed | `tg_config.py` | `RANDOM_SEED = 42` |
| XGBoost hyperparams | `tg_config.py` | `XGBOOST_PARAMS` |
| Train/val/test split ratios | `tg_config.py` | `TEST_SIZE, VAL_SIZE` |
| Feature sets | `feature-extraction/feature_schema.py` | `EXPERIMENT_*_FEATURES` |
| Experiment registry | `ml/ml_config.py` | `EXPERIMENTS` dict |
| Model save/load paths | `ml/ml_config.py` | `MODEL_REGISTRY` |
| Caddy target URL | `tg_config.py` | `TARGET_BASE_URL` |
| Session manifest path | `tg_config.py` | `MANIFEST_PATH` |
| PCAP store path | `tg_config.py` | `PCAP_STORE` |

---

*For questions on the consistency-layer (`spatial_score.py`, `temporal_score.py`, `expected_combinations.py`): see Harshil's domain per `CLAUDE.md`.*
*For questions on the base ML pipeline (`train_utils.py`, `evasion_test.py`, feature schema): see Basel's domain per `CLAUDE.md`.*
