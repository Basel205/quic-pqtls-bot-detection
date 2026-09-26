"""
Group-level evasion evaluation — the "burn the whole identity" idea: a real
deployment tracks a client over repeat visits, so if ANY session from a
client_identity_id gets flagged, every session from that identity can be
blocked, not just the one flagged session. A per-session-only evasion rate
(what ml/evasion_test.py reports) undersells this, because it scores every
session independently even when the model has cross-session information for
free.

This script reports TWO versions of that idea for D2, and prints both,
because the naive one is not automatically a win (see CLAUDE.md's write-up of
the first attempt — it actually did WORSE than a naive group rule for B in
that run, precisely because per-session score noise on a small session count
per identity (3-5) can go either way):

  1. NAIVE: flag the whole group if ANY session in it was individually
     misclassified as non-human by the trained model. Computed identically
     for B_enhanced_retrained and D2_spatial_temporal_retrained so the
     comparison is fair — this is what "burn the group" naively means.

  2. THRESHOLD-SWEPT (D2 only): flag the whole group if the MAX
     temporal_inconsistency_score across the group's sessions exceeds a
     threshold, swept across several values. This uses the actual continuous
     signal instead of a binary "did the classifier individually catch this"
     proxy, and is closer to what a real deployment would tune.

IMPORTANT: the threshold in (2) must be chosen on a VALIDATION split, not the
evasion TEST split, before it's reported as a final number — sweeping it here
and picking whichever value looks best on the test set would be quietly
fitting the test set. This script prints the sweep so you can see the shape
of the curve and pick a principled threshold (e.g. the one that best
separates degraded-group scores from clean-group scores on the TRAINING
data's tier4-train groups), not to hand-pick the best test-set number.

Run after ml/split_tier4.py, ml/train_retrained.py, and ml/evasion_test.py.
"""
import sys
from pathlib import Path

import joblib
import pandas as pd

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
from _paths import setup_paths; setup_paths(_ROOT)
sys.path.insert(0, str(_ROOT / "consistency-layer"))

from tg_config import MANIFEST_PATH
from feature_schema import EXPERIMENT_B_FEATURES, EXPERIMENT_D2_FEATURES, LABEL_MAP_INV
from expected_combinations import build_expected_combinations
from spatial_score import score_dataframe as score_spatial
from temporal_score import compute_temporal_scores

TIER4_DATASET_PATH = Path(__file__).parent / "tier4_dataset.parquet"
TIER4_TEST_IDS_PATH = Path(__file__).parent / "tier4_test_ids.csv"
MODEL_REGISTRY = Path(__file__).parent / "model_registry"

THRESHOLD_SWEEP = [0.0, 0.05, 0.1, 0.15, 0.2, 0.25, 0.3]


def _load_test_set() -> pd.DataFrame:
    if not TIER4_TEST_IDS_PATH.exists():
        raise FileNotFoundError("ml/tier4_test_ids.csv not found — run ml/split_tier4.py first.")
    # IMPORTANT: score on the full tier4 set BEFORE filtering to test_ids, not
    # after. temporal_score.py's compute_temporal_scores() writes results back
    # via `scores.loc[idxs[i]]` where idxs comes from a post-merge index that
    # only lines up with df's own index when df has a clean 0..n-1 RangeIndex
    # (true for a freshly-loaded parquet, false after boolean-mask filtering,
    # which keeps the original non-contiguous positions). Filtering first
    # silently produces mostly-zero scores instead of raising an error — see
    # IMPLEMENTATION.md for the underlying fix needed in temporal_score.py
    # itself. Scoring before filtering sidesteps it here.
    tier4 = pd.read_parquet(TIER4_DATASET_PATH).reset_index(drop=True)
    table = build_expected_combinations()
    tier4["spatial_inconsistency_score"] = score_spatial(tier4, table)
    tier4["temporal_inconsistency_score"] = compute_temporal_scores(tier4, manifest_path=MANIFEST_PATH)

    test_ids = set(pd.read_csv(TIER4_TEST_IDS_PATH)["session_id"])
    df = tier4[tier4["session_id"].isin(test_ids)].copy()
    manifest = pd.read_csv(MANIFEST_PATH)[["session_id", "client_identity_id"]]
    df = df.merge(manifest, on="session_id", how="left")
    return df


def _predict(model_name: str, features: list[str], df: pd.DataFrame) -> pd.Series:
    model = joblib.load(MODEL_REGISTRY / f"{model_name}.joblib")
    pred = model.predict(df[features])
    return pd.Series([LABEL_MAP_INV[p] for p in pred], index=df.index)


def naive_group_rule(df: pd.DataFrame, pred_col: str, model_name: str) -> None:
    df["_caught"] = df[pred_col] != "human"
    group_flag = df.groupby("client_identity_id")["_caught"].any()
    n_groups = len(group_flag)
    n_groups_caught = int(group_flag.sum())
    caught_ids = group_flag[group_flag].index
    n_sessions_burned = int(df["client_identity_id"].isin(caught_ids).sum())
    print(f"  {model_name:30s} groups: {n_groups_caught}/{n_groups} flagged  "
          f"-> {n_sessions_burned}/{len(df)} sessions would be burned "
          f"({n_sessions_burned/len(df):.1%} caught, {1-n_sessions_burned/len(df):.1%} evasion)")


def threshold_swept_rule(df: pd.DataFrame) -> None:
    group_max_score = df.groupby("client_identity_id")["temporal_inconsistency_score"].max()
    n_groups = len(group_max_score)
    print(f"\n  D2 temporal score, group-max, swept threshold (n={n_groups} groups, {len(df)} sessions):")
    print(f"  {'threshold':>10s}  {'groups flagged':>15s}  {'sessions burned':>16s}  {'evasion rate':>12s}")
    for t in THRESHOLD_SWEEP:
        flagged = group_max_score > t
        n_flagged_groups = int(flagged.sum())
        caught_ids = flagged[flagged].index
        n_burned = int(df["client_identity_id"].isin(caught_ids).sum())
        evasion = 1 - n_burned / len(df)
        print(f"  {t:>10.2f}  {n_flagged_groups:>15d}  {n_burned:>16d}  {evasion:>11.1%}")


def main():
    df = _load_test_set()
    df["pred_B"] = _predict("B_enhanced_retrained", EXPERIMENT_B_FEATURES, df)
    df["pred_D2"] = _predict("D2_spatial_temporal_retrained", EXPERIMENT_D2_FEATURES, df)

    print(f"[group_level_eval] {df['client_identity_id'].nunique()} identity groups, "
          f"{len(df)} sessions in the held-out tier4 test split\n")

    print("1) NAIVE any-catch group rule (fair comparison, same rule for both):")
    naive_group_rule(df, "pred_B", "B_enhanced_retrained")
    naive_group_rule(df, "pred_D2", "D2_spatial_temporal_retrained")

    print("\n2) Threshold-swept group rule using D2's continuous temporal score directly:")
    threshold_swept_rule(df)
    print("\n  NOTE: pick the threshold on a validation split before reporting a final "
          "number — this sweep is for choosing it, not for reading off whichever row "
          "looks best on this test set.")


if __name__ == "__main__":
    main()
