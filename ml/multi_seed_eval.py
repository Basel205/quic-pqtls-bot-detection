"""
Multi-seed robustness check for the Tier-4 retrain result. A single seed
gives one particular 60/40 group split and one particular model fit — this
script reruns the whole thing across several seeds and reports the SPREAD of
the evasion rate, which is the honest way to answer "is this number stable"
instead of reporting one run as if it were exact.

Deliberately self-contained (doesn't modify split_tier4.py / train_utils.py /
evasion_test.py) so it can't destabilize the pipeline those already-verified
files run — it re-implements the same three steps inline, parameterized by
seed, reusing the same scoring functions everything else uses.

Run after the base dataset.parquet / tier4_dataset.parquet already exist
(i.e. after ml/evasion_test.py has been run at least once).
"""
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.model_selection import train_test_split

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
from _paths import setup_paths; setup_paths(_ROOT)
sys.path.insert(0, str(_ROOT / "consistency-layer"))

from ml_config import DATASET_PATH, TEST_SIZE, VAL_SIZE, XGBOOST_PARAMS
from feature_schema import (
    EXPERIMENT_B_FEATURES, EXPERIMENT_D1_FEATURES, EXPERIMENT_D2_FEATURES,
    LABEL_COL, LABEL_MAP, LABEL_MAP_INV,
)
from tg_config import MANIFEST_PATH
from expected_combinations import build_expected_combinations
from spatial_score import score_dataframe as score_spatial
from temporal_score import compute_temporal_scores

TIER4_DATASET_PATH = Path(__file__).parent / "tier4_dataset.parquet"
SEEDS = [42, 1, 7, 123, 2024]
TRAIN_FRACTION = 0.6


def split_tier4_for_seed(tier4: pd.DataFrame, manifest: pd.DataFrame, seed: int):
    t4m = tier4.merge(manifest[["session_id", "client_identity_id"]], on="session_id", how="left")
    groups = np.array(sorted(t4m["client_identity_id"].unique()), dtype=object)
    rng = np.random.RandomState(seed)
    groups = groups[rng.permutation(len(groups))]
    n_train = int(round(len(groups) * TRAIN_FRACTION))
    train_groups, test_groups = set(groups[:n_train]), set(groups[n_train:])
    train_df = t4m[t4m["client_identity_id"].isin(train_groups)].drop(columns=["client_identity_id"])
    test_df = t4m[t4m["client_identity_id"].isin(test_groups)].drop(columns=["client_identity_id"])
    return train_df, test_df


def train_one(features, combined: pd.DataFrame, seed: int):
    X, y = combined[features], combined[LABEL_COL].map(LABEL_MAP)
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=(TEST_SIZE + VAL_SIZE), random_state=seed, stratify=y)
    params = dict(XGBOOST_PARAMS); params["random_state"] = seed
    model = xgb.XGBClassifier(**params)
    model.fit(X_train, y_train)
    return model


def evasion_rate(model, features, test_df: pd.DataFrame) -> float:
    pred = model.predict(test_df[features])
    labels = [LABEL_MAP_INV[p] for p in pred]
    return sum(1 for l in labels if l == "human") / len(labels)


def run_seed(dataset: pd.DataFrame, tier4: pd.DataFrame, manifest: pd.DataFrame, seed: int) -> dict:
    tier4_train, tier4_test = split_tier4_for_seed(tier4, manifest, seed)
    combined = pd.concat([dataset, tier4_train], ignore_index=True)

    table = build_expected_combinations()
    combined["spatial_inconsistency_score"] = score_spatial(combined, table)
    combined["temporal_inconsistency_score"] = compute_temporal_scores(combined, manifest_path=MANIFEST_PATH)
    tier4_test = tier4_test.reset_index(drop=True)
    tier4_test["spatial_inconsistency_score"] = score_spatial(tier4_test, table)
    tier4_test["temporal_inconsistency_score"] = compute_temporal_scores(tier4_test, manifest_path=MANIFEST_PATH)

    model_B = train_one(EXPERIMENT_B_FEATURES, combined, seed)
    model_D1 = train_one(EXPERIMENT_D1_FEATURES, combined, seed)
    model_D2 = train_one(EXPERIMENT_D2_FEATURES, combined, seed)

    return {
        "seed": seed,
        "n_test_sessions": len(tier4_test),
        "B_enhanced_retrained": evasion_rate(model_B, EXPERIMENT_B_FEATURES, tier4_test),
        "D1_spatial_retrained": evasion_rate(model_D1, EXPERIMENT_D1_FEATURES, tier4_test),
        "D2_spatial_temporal_retrained": evasion_rate(model_D2, EXPERIMENT_D2_FEATURES, tier4_test),
    }


def main():
    dataset = pd.read_parquet(DATASET_PATH)
    tier4 = pd.read_parquet(TIER4_DATASET_PATH)
    manifest = pd.read_csv(MANIFEST_PATH)

    rows = []
    for seed in SEEDS:
        r = run_seed(dataset, tier4, manifest, seed)
        rows.append(r)
        print(f"seed={seed:5d}  n_test={r['n_test_sessions']:3d}  "
              f"B={r['B_enhanced_retrained']:.1%}  D1={r['D1_spatial_retrained']:.1%}  "
              f"D2={r['D2_spatial_temporal_retrained']:.1%}")

    df = pd.DataFrame(rows)
    print("\nSummary across", len(SEEDS), "seeds:")
    for col in ["B_enhanced_retrained", "D1_spatial_retrained", "D2_spatial_temporal_retrained"]:
        print(f"  {col:32s} mean={df[col].mean():.1%}  std={df[col].std():.1%}  "
              f"min={df[col].min():.1%}  max={df[col].max():.1%}")

    df.to_csv(Path(__file__).parent / "results" / "multi_seed_evasion.csv", index=False)


if __name__ == "__main__":
    main()
