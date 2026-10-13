# Research Changes & Improvements Log

> **Branch:** `results-and-paper`
> **Author:** Basel205
> **Date:** October 2026

---

## Summary

This document explains every change made during the latest research improvement cycle — what results looked like before, what was changed, and why the new results are better.

---

## 1. Where We Started (Previous Results)

The original pipeline (`feature` branch baseline) had:

| Model | Evasion Rate (Tier-4) | Notes |
|---|---|---|
| B_enhanced (frozen) | 97.3% | Collapses under Tier-4 |
| D1_spatial (frozen) | 97.3% | Spatial adds nothing frozen |
| D2_spatial_temporal (frozen) | 97.3% | All frozen models collapse |
| B_enhanced_retrained | 58.1% | Retraining partially recovers |
| D1_spatial_retrained | 59.5% | Spatial still adds nothing |
| D2_spatial_temporal_retrained | 18.9% | Temporal is the key signal |

**Problem:** 18.9% was achieved with default XGBoost hyperparameters and no class weighting. Tier-4 is severely under-represented (200/1820 sessions), so the model wasn't penalizing Tier-4 misclassification enough.

---

## 2. New Models Added (ml/train_optimized.py)

### D2_tuned
- Added 2.74x sample_weight on bot_t4 training rows (compensates class imbalance)
- Applied RandomizedSearchCV (20 trials, 3-fold CV): n_estimators=200, max_depth=7, lr=0.1, gamma=0.5
- **Evasion: 18.9% -> 14.9% (seed 42), 18.1+-4.4% -> 16.5+-4.8% (multi-seed mean)**
- ROC-AUC: 0.9317 -> 0.943 | PR-AUC: 0.8823 -> 0.905

### D2_ensemble
- Soft-vote ensemble of tuned XGBoost + tuned LightGBM
- Achieves identical 16.5% multi-seed mean — confirms gain is from weighting/tuning, not model family

### Output files:
- ml/results/D2_tuned.json
- ml/results/D2_ensemble.json
- ml/results/multi_seed_optimized.csv
- ml/model_registry/D2_tuned.joblib
- ml/model_registry/D2_ensemble_xgb.joblib
- ml/model_registry/D2_ensemble_lgb.joblib

---

## 3. New Figures

| File | Description |
|---|---|
| figures/roc_B_vs_D2.png | ROC: B_retrained vs D2_retrained on Tier-4 |
| figures/shap_D2_spatial_temporal_retrained.png | TreeSHAP importance for D2 retrained |
| figures/evasion_progression.png (NEW) | Bar chart: 58.1% -> 18.9% -> 16.5% -> 14.9% |
| figures/roc_pr_tier4_comparison.png (NEW) | ROC + PR curves for all model variants |

---

## 4. Paper Changes (IEEE_Conference_Paper.tex)

### Abstract and Introduction
- Updated to include 14.9% result and 16.5+-4.8% multi-seed numbers
- Added ROC-AUC 0.943 and PR-AUC 0.905 figures
- Contribution list updated with tuned/ensemble models

### Table VII (Multi-seed) — tab:multiseed
- Before: 4 columns (Seed, Sessions, B-evasion, D2-baseline)
- After: 6 columns (added D2-tuned and D2-ensemble columns)
- Changed from table to table* (full-width) because 6 columns exceeds single column width

### New Section V-D — Group-Level Aggregation and Class Weighting
- Documents Noisy-OR group detection (81.0% group detection at tau=0.95)
- Explains class weighting (2.74x) and hyperparameter tuning steps
- New figures evasion_progression and roc_pr_tier4_comparison inserted here

### Table Overlap Fix (IEEEtran two-column rendering)
Tables III and V were visually overlapping in the PDF output because Table III exceeded column width.

| Table | Problem | Fix Applied |
|---|---|---|
| Table III (tab:in_dist) | Exceeded column width — no size constraint | Added resizebox{\columnwidth}{!} |
| Table V (tab:retrained) | Float specifier [h!] conflicted with IEEEtran | Changed to [t] |
| Table VI (tab:isolate) | Long labels risked overflow | Added resizebox{\columnwidth}{!} |
| Table VII (tab:multiseed) | 6 columns too wide for single column | Changed table -> table* |

---

## 5. Root figures/ Directory (NEW)

The LaTeX source references figures/roc_B_vs_D2.png etc. as relative paths.
Figures were previously only in ml/figures/ — Overleaf could not find them.

Fix: Copied ml/figures/ into a root-level figures/ directory matching paper paths.

To upload to Overleaf alongside the .tex file:
  IEEE_Conference_Paper.tex
  figures/
    roc_B_vs_D2.png
    shap_D2_spatial_temporal_retrained.png
    evasion_progression.png
    roc_pr_tier4_comparison.png

---

## 6. Full Results Comparison

### Adversarial Evasion — Tier-4 Adaptive Bot (n=74 held-out)

| Model | Evasion | Change |
|---|---|---|
| All frozen timing models | 97.3% | Baseline collapse |
| B_enhanced_retrained | 58.1% | -39.2pp from frozen |
| D1_spatial_retrained | 59.5% | No improvement |
| D2_spatial_temporal_retrained | 18.9% | Temporal = key signal |
| D2_tuned | 14.9% | Class weight + tuning |
| D2_ensemble | 14.9% | Confirmed across model families |

### Multi-Seed Stability

| Seed | B-retrained | D2-baseline | D2-tuned | D2-ensemble |
|---|---|---|---|---|
| 42 | 58.1% | 18.9% | 14.9% | 14.9% |
| 1 | 67.1% | 21.5% | 20.3% | 20.3% |
| 7 | 67.5% | 22.9% | 22.9% | 22.9% |
| 123 | 58.5% | 13.4% | 12.2% | 11.0% |
| 2024 | 61.3% | 13.8% | 12.5% | 13.8% |
| Mean +- Std | 62.5+-4.5% | 18.1+-4.4% | 16.5+-4.8% | 16.5+-4.9% |

---

## 7. Core Insight

Temporal fingerprint consistency is the only signal that survives an adaptive adversary. All protocol features (PQ, QUIC, spatial scores) collapse at 97.3% evasion once the bot mimics timing.

The improvement from 18.9% to 14.9% is NOT from a new defensive signal. It is from:
1. Class weighting (2.74x) — telling the model to care more about the rare Tier-4 class
2. Hyperparameter tuning (RandomizedSearchCV) — better tree configuration
3. Ensemble validation — confirming the gain holds across XGBoost and LightGBM
