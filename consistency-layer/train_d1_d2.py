"""
FILE 3 of 5 — Train D1, D2, and the three *_retrained arms.

Changes from original:
1. _ensure_scores_current() now builds the combined dataframe (Tiers 1-3
   base dataset + Tier-4 training sessions) before computing scores. This
   ensures the score CSVs contain rows for every session that will appear
   in the combined training set — without this, the LEFT merge in
   train_utils.load_dataset_for_experiment() silently drops Tier-4 rows,
   meaning the retrained arms would still train on 1,600 sessions (the
   original bug identified during plan review).

2. Trains five experiments, not two:
     - D1_spatial             (original, Tiers 1-3 only — preserved for "before" comparison)
     - D2_spatial_temporal    (original, Tiers 1-3 only — preserved for "before" comparison)
     - B_enhanced_retrained   (control arm — same data as D1/D2 retrained, different features)
     - D1_spatial_retrained
     - D2_spatial_temporal_retrained   ← primary result

   ALL three retrained arms must use the same combined dataset so the only
   variable between them is the feature set. train_utils.train_and_evaluate()
   handles this automatically for any experiment name ending in "_retrained".

Run order (CLAUDE.md execution order):
    python ml/split_tier4.py          # once, before this script
    python consistency-layer/train_d1_d2.py
    python ml/evasion_test.py
"""
import json
import sys
from pathlib import Path

import pandas as pd

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))
from _paths import setup_paths; setup_paths(_ROOT)

from expected_combinations import build_expected_combinations
from spatial_score import score_dataframe as score_spatial
from temporal_score import compute_temporal_scores
from tg_config import DATASET_PATH, MANIFEST_PATH
from train_utils import train_and_evaluate

CONSISTENCY_LAYER  = Path(__file__).parent
SPATIAL_SCORES_CSV = CONSISTENCY_LAYER / "d1_spatial_scores.csv"
TEMPORAL_SCORES_CSV = CONSISTENCY_LAYER / "d2_temporal_scores.csv"

TIER4_TRAIN_IDS    = _ROOT / "ml" / "tier4_train_ids.csv"
TIER4_DATASET_PATH = _ROOT / "ml" / "tier4_dataset.parquet"


def _build_combined_df() -> pd.DataFrame:
    """
    Returns the combined training dataframe: Tiers 1-3 base (1,600 sessions)
    concatenated with the Tier-4 training sessions designated by split_tier4.py.

    This combined frame is used ONLY for computing the score CSVs — the actual
    training split (70/15/15) happens inside train_and_evaluate(). The score
    CSVs must cover every row that will appear in the combined training set;
    if they don't, the merge in load_dataset_for_experiment() produces NaN
    scores for the missing rows (Tier-4 sessions), which XGBoost would treat
    as missing values and the consistency signal would be degraded.
    """
    base_df = pd.read_parquet(DATASET_PATH)

    if not TIER4_TRAIN_IDS.exists():
        print(
            "[train_d1_d2] WARNING: tier4_train_ids.csv not found — "
            "scores will be computed on base dataset only (1,600 sessions). "
            "Run ml/split_tier4.py first to include Tier-4 training data."
        )
        return base_df

    if not TIER4_DATASET_PATH.exists():
        print(
            "[train_d1_d2] WARNING: tier4_dataset.parquet not found — "
            "scores will be computed on base dataset only. "
            "Run ml/evasion_test.py first to build it from pcaps."
        )
        return base_df

    train_ids = set(pd.read_csv(TIER4_TRAIN_IDS)["session_id"].tolist())
    t4_df = pd.read_parquet(TIER4_DATASET_PATH)
    t4_train = t4_df[t4_df["session_id"].isin(train_ids)].copy()

    combined = pd.concat([base_df, t4_train], ignore_index=True)
    print(
        f"[train_d1_d2] Combined dataset: {len(base_df)} base + "
        f"{len(t4_train)} Tier-4 train = {len(combined)} total sessions."
    )
    return combined


def _ensure_scores_current() -> None:
    """
    (Re)computes both score CSVs from the combined dataset before training.
    The CSVs must cover all sessions (base + Tier-4 train) so that the merge
    in load_dataset_for_experiment() finds a score for every training row.
    """
    df = _build_combined_df()

    table = build_expected_combinations()
    df["spatial_inconsistency_score"] = score_spatial(df, table)
    df[["session_id", "label", "spatial_inconsistency_score"]].to_csv(
        SPATIAL_SCORES_CSV, index=False
    )
    print(f"[train_d1_d2] Spatial scores written → {SPATIAL_SCORES_CSV} ({len(df)} rows)")

    df["temporal_inconsistency_score"] = compute_temporal_scores(df, manifest_path=MANIFEST_PATH)
    df[["session_id", "label", "temporal_inconsistency_score"]].to_csv(
        TEMPORAL_SCORES_CSV, index=False
    )
    print(f"[train_d1_d2] Temporal scores written → {TEMPORAL_SCORES_CSV} ({len(df)} rows)")

    # Quick sanity check: Tier-4 degraded sessions should have high spatial score.
    t4_rows = df[df["label"] == "bot_t4"]
    if len(t4_rows) > 0:
        print(f"\n[train_d1_d2] Tier-4 spatial score distribution (sanity check):")
        print(t4_rows.groupby(df["used_http3"])["spatial_inconsistency_score"].describe().to_string())
        print(f"\n[train_d1_d2] Tier-4 temporal score distribution:")
        print(t4_rows["temporal_inconsistency_score"].describe().to_string())


if __name__ == "__main__":
    # Step 1: recompute scores on combined data
    _ensure_scores_current()

    results = {}

    # Step 2: original D1/D2 (Tiers 1-3 only) — preserved for "before" comparison
    print("\n" + "="*60)
    print("Training original D1/D2 (base dataset, no Tier-4 train data)")
    print("="*60)
    for experiment in ["D1_spatial", "D2_spatial_temporal"]:
        result = train_and_evaluate(experiment)
        results[experiment] = {k: v for k, v in result.items() if k != "features"}
        print(f"\n=== {experiment} ===")
        print(json.dumps(results[experiment], indent=2))

    # Step 3: retrained arms (combined data) — the actual fix
    print("\n" + "="*60)
    print("Training retrained arms (combined dataset: base + Tier-4 train)")
    print("="*60)
    for experiment in ["B_enhanced_retrained", "D1_spatial_retrained", "D2_spatial_temporal_retrained"]:
        result = train_and_evaluate(experiment)
        results[experiment] = {k: v for k, v in result.items() if k != "features"}
        print(f"\n=== {experiment} ===")
        print(json.dumps(results[experiment], indent=2))

    print("\n" + "="*60)
    print("ALL TRAINING COMPLETE — now run: python ml/evasion_test.py")
    print("="*60)
