"""
Phase 5 evasion test — CLAUDE.md's Phase-gating rule treats this as a
required primary outcome, not optional: does consistency-augmented detection
(D1/D2) hold its advantage against an adaptive Tier-4 bot built with full
knowledge of the feature set, better than presence-only detection (B)?

Tier 4 sessions are intentionally NOT part of dataset.parquet — that file
stays the fixed 1,600-session A/B/D1/D2 training set (see CLAUDE.md's Key
Locked Technical Facts). Features are extracted directly from Tier 4's pcaps
here into a separate ml/tier4_dataset.parquet, so this script never touches
or rebuilds the main dataset file. Reuses build_dataset.py's per-pcap
extractor and consistency-layer's scoring functions rather than duplicating
either.

If ml/tier4_test_ids.csv exists (written by split_tier4.py), every model in
this comparison — frozen originals AND the *_retrained variants — is
evaluated on that TEST-split subset only, not the full 200 sessions. This
keeps the before/after comparison table apples-to-apples: the *_retrained
models were trained on the TRAIN-split sessions, so scoring everyone on the
same held-out TEST-split sessions is the only fair way to read "did
retraining help" off the resulting numbers. Falls back to the full 200
sessions (with a warning) if split_tier4.py hasn't been run yet.

Metric: for each already-trained model, the fraction of bot_t4 sessions it
misclassifies as "human" — i.e. the evasion rate. Lower is better (more
evasion-resistant).
"""
import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

import joblib
import pandas as pd

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
from _paths import setup_paths; setup_paths(_ROOT)
# setup_paths() doesn't include consistency-layer/ (it's not one of Basel's
# core dirs) — added explicitly for the D1/D2 scoring imports below.
sys.path.insert(0, str(_ROOT / "consistency-layer"))

from tg_config import PCAP_STORE, MANIFEST_PATH
from feature_schema import (
    EXPERIMENT_A_FEATURES,
    EXPERIMENT_B_FEATURES,
    EXPERIMENT_D1_FEATURES,
    EXPERIMENT_D2_FEATURES,
    EXPERIMENT_SPATIAL_ONLY_FEATURES,
    EXPERIMENT_FULL_CONSISTENCY_FEATURES,
    LABEL_MAP_INV,
)
from build_dataset import extract_features_for_pcap, write_to_sqlite
from expected_combinations import build_expected_combinations
from spatial_score import score_dataframe as score_spatial_dataframe
from temporal_score import compute_temporal_scores

TIER4_DATASET_PATH = Path(__file__).parent / "tier4_dataset.parquet"
TIER4_TEST_IDS_PATH = Path(__file__).parent / "tier4_test_ids.csv"
MODEL_REGISTRY      = Path(__file__).parent / "model_registry"
RESULTS_DIR         = Path(__file__).parent / "results"

# A_baseline included for completeness (it uses none of the novel signals so
# an adaptive bot gains nothing from spoofing PQ/QUIC/timing against it), but
# the real comparison this test exists for is B vs. D1/D2, frozen vs. retrained.
EVASION_MODELS = [
    "A_baseline", "B_enhanced", "D1_spatial", "D2_spatial_temporal",
    "Ablation_spatial_only", "Ablation_full_consistency",
    "B_enhanced_retrained", "D1_spatial_retrained", "D2_spatial_temporal_retrained",
]
MODEL_FEATURES = {
    "A_baseline":                    EXPERIMENT_A_FEATURES,
    "B_enhanced":                    EXPERIMENT_B_FEATURES,
    "D1_spatial":                    EXPERIMENT_D1_FEATURES,
    "D2_spatial_temporal":           EXPERIMENT_D2_FEATURES,
    "Ablation_spatial_only":         EXPERIMENT_SPATIAL_ONLY_FEATURES,
    "Ablation_full_consistency":     EXPERIMENT_FULL_CONSISTENCY_FEATURES,
    "B_enhanced_retrained":          EXPERIMENT_B_FEATURES,
    "D1_spatial_retrained":          EXPERIMENT_D1_FEATURES,
    "D2_spatial_temporal_retrained": EXPERIMENT_D2_FEATURES,
}


def build_tier4_dataset(rebuild: bool = False) -> pd.DataFrame:
    """Extract raw features for every bot_t4 pcap. Cached to
    tier4_dataset.parquet; pass rebuild=True to re-extract from pcaps."""
    if TIER4_DATASET_PATH.exists() and not rebuild:
        return pd.read_parquet(TIER4_DATASET_PATH)

    manifest_rows = list(csv.DictReader(open(MANIFEST_PATH, encoding="utf-8")))
    t4_rows = [r for r in manifest_rows if r["label"] == "bot_t4"]
    if not t4_rows:
        raise RuntimeError("No bot_t4 sessions found in session_manifest.csv — run session_orchestrator.py --tier bot_t4 first.")

    rows = []
    for r in t4_rows:
        sid = r["session_id"]
        pcap_path = PCAP_STORE / f"{sid}.pcap"
        if not pcap_path.exists() or pcap_path.stat().st_size == 0:
            print(f"[evasion_test] SKIP {sid} — missing/empty pcap")
            continue
        try:
            fv = extract_features_for_pcap(pcap_path, sid, "bot_t4")
        except Exception as e:
            print(f"[evasion_test] ERROR on {sid}: {e}")
            continue
        write_to_sqlite(fv)
        rows.append(fv.to_dict())

    df = pd.DataFrame(rows)
    df.to_parquet(TIER4_DATASET_PATH, index=False)
    print(f"[evasion_test] {len(df)} bot_t4 sessions -> {TIER4_DATASET_PATH}")
    return df


def _filter_to_test_split(df: pd.DataFrame) -> pd.DataFrame:
    """Restricts df to the TEST-split session_ids written by split_tier4.py,
    so frozen and retrained models are compared on identical held-out
    sessions. If split_tier4.py hasn't been run, evaluates on all of df
    instead (matches the original, pre-retrain-fix behavior)."""
    if not TIER4_TEST_IDS_PATH.exists():
        print(f"[evasion_test] {TIER4_TEST_IDS_PATH} not found — evaluating on "
              f"all {len(df)} tier4 sessions. Run split_tier4.py first for a fair "
              f"frozen-vs-retrained comparison.")
        return df

    test_ids = set(pd.read_csv(TIER4_TEST_IDS_PATH)["session_id"])
    filtered = df[df["session_id"].isin(test_ids)]
    n_excluded = len(df) - len(filtered)
    print(f"[evasion_test] Filtered to held-out test sessions: {len(filtered)}/{len(df)} "
          f"sessions ({n_excluded} training sessions excluded from evasion test).")
    return filtered


def add_consistency_scores(df: pd.DataFrame) -> pd.DataFrame:
    """Joins in D1's spatial score (against the human-derived expected-
    combination table) and D2's temporal score (drift within each bot_t4
    session's own client_identity_id group). Scored BEFORE the train/test
    filter is applied to the full tier4 set, so a test-split session's
    temporal score still reflects its real siblings — some of which may be
    on the train side, which is fine: the score is a read of what actually
    happened on the wire, not something derived from a trained model, so
    there's no leakage in computing it this way. What must never happen is a
    train-split session's score being computed after the fact from
    test-split siblings' train-time labels; that isn't done here."""
    table = build_expected_combinations()
    df = df.copy()
    df["spatial_inconsistency_score"] = score_spatial_dataframe(df, table)
    df["temporal_inconsistency_score"] = compute_temporal_scores(df, manifest_path=MANIFEST_PATH)
    return df


def run_evasion_test(rebuild: bool = False) -> dict:
    df = build_tier4_dataset(rebuild=rebuild)
    df = add_consistency_scores(df)
    df = _filter_to_test_split(df)

    results = {"n_bot_t4_sessions": len(df)}
    print(f"\n[evasion_test] {len(df)} bot_t4 sessions, evaluating {len(EVASION_MODELS)} trained models:\n")

    for exp in EVASION_MODELS:
        model_path = MODEL_REGISTRY / f"{exp}.joblib"
        if not model_path.exists():
            print(f"  {exp}: SKIP — {model_path} not found (train it first)")
            continue

        model = joblib.load(model_path)
        X = df[MODEL_FEATURES[exp]]
        pred = model.predict(X)
        pred_labels = [LABEL_MAP_INV[p] for p in pred]

        n = len(pred_labels)
        n_evaded = sum(1 for p in pred_labels if p == "human")
        evasion_rate = n_evaded / n if n else 0.0
        dist = dict(Counter(pred_labels))

        results[exp] = {
            "n_sessions":              n,
            "n_evaded_as_human":       n_evaded,
            "evasion_rate":            evasion_rate,
            "prediction_distribution": dist,
            # per-session predictions, aligned to df's session_id column —
            # kept in the JSON specifically so group_level_eval.py (and any
            # manual "which sessions did D2 catch that B missed" check) can
            # be done from the saved results without re-running inference.
            "session_ids":             df["session_id"].tolist(),
            "predictions":             pred_labels,
        }
        print(f"  {exp:30s} — {n_evaded:3d}/{n} misclassified as human "
              f"({evasion_rate:.1%} evasion rate)   predictions: {dist}")

    RESULTS_DIR.mkdir(exist_ok=True)
    with open(RESULTS_DIR / "evasion_test.json", "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[evasion_test] Results saved to {RESULTS_DIR / 'evasion_test.json'}")
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Phase 5 evasion test — B vs. D1/D2 against Tier-4 adaptive bot")
    parser.add_argument("--rebuild", action="store_true", help="Re-extract tier4 features from pcaps even if tier4_dataset.parquet exists")
    args = parser.parse_args()
    run_evasion_test(rebuild=args.rebuild)
