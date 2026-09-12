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

Metric: for each already-trained model (B_enhanced, D1_spatial,
D2_spatial_temporal), the fraction of bot_t4 sessions it misclassifies as
"human" — i.e. the evasion rate. Lower is better (more evasion-resistant).
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
MODEL_REGISTRY      = Path(__file__).parent / "model_registry"
RESULTS_DIR         = Path(__file__).parent / "results"

# A_baseline included for completeness (it uses none of the novel signals so
# an adaptive bot gains nothing from spoofing PQ/QUIC/timing against it), but
# the real comparison this test exists for is B vs. D1/D2.
EVASION_MODELS = [
    "A_baseline", "B_enhanced", "D1_spatial", "D2_spatial_temporal",
    "Ablation_spatial_only", "Ablation_full_consistency",
]
MODEL_FEATURES = {
    "A_baseline":               EXPERIMENT_A_FEATURES,
    "B_enhanced":                EXPERIMENT_B_FEATURES,
    "D1_spatial":                EXPERIMENT_D1_FEATURES,
    "D2_spatial_temporal":       EXPERIMENT_D2_FEATURES,
    "Ablation_spatial_only":     EXPERIMENT_SPATIAL_ONLY_FEATURES,
    "Ablation_full_consistency": EXPERIMENT_FULL_CONSISTENCY_FEATURES,
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


def add_consistency_scores(df: pd.DataFrame) -> pd.DataFrame:
    """Joins in D1's spatial score (against the human-derived expected-
    combination table) and D2's temporal score (drift within each bot_t4
    session's own client_identity_id group — tier4 groups never share a
    client_identity_id with any other tier, so this only ever compares a
    bot_t4 session against its bot_t4 siblings)."""
    table = build_expected_combinations()
    df = df.copy()
    df["spatial_inconsistency_score"] = score_spatial_dataframe(df, table)
    df["temporal_inconsistency_score"] = compute_temporal_scores(df, manifest_path=MANIFEST_PATH)
    return df


def run_evasion_test(rebuild: bool = False) -> dict:
    df = build_tier4_dataset(rebuild=rebuild)
    df = add_consistency_scores(df)

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
        }
        print(f"  {exp:22s} — {n_evaded:3d}/{n} misclassified as human "
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
