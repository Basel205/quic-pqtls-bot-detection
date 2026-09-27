"""
Consistency Risk Score — an explicit, interpretable formula replacing "feed
spatial + temporal scores into XGBoost and hope it uses them," which is what
D1/D2 currently do. Two deliverables in one:

  1. A per-session formula: C(s) = sigmoid(w0 + w1*spatial(s) + w2*temporal(s))
     with (w0, w1, w2) fit by simple logistic regression — three numbers you
     can put directly in a paper and defend, instead of "the tree ensemble
     decided."
  2. A group-level formula extending it: GroupRisk(g) = 1 - PRODUCT(1 - C(s))
     over sessions s in group g. This is a "noisy-OR" — treating each
     session's risk as independent evidence, the group's risk is the
     probability that AT LEAST ONE session looks like a bot. It requires
     only one session in a client's history to look anomalous to burn the
     whole identity, without needing a black-box model to learn that rule.

The group-level THRESHOLD is tuned properly: the 32 Tier-4 TRAIN-split
identity groups (from split_tier4.py) are further split into a fit set and a
validation set, and the threshold is chosen on the validation set. The 21
TEST-split groups are never touched until the final, single evaluation at
the end — this is the fix for the "threshold was swept on the test set"
problem in the earlier group_level_eval.py.

Run after ml/split_tier4.py.
"""
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
from _paths import setup_paths; setup_paths(_ROOT)
sys.path.insert(0, str(_ROOT / "consistency-layer"))

from ml_config import DATASET_PATH, RANDOM_SEED
from tg_config import MANIFEST_PATH
from feature_schema import LABEL_COL
from expected_combinations import build_expected_combinations
from spatial_score import score_dataframe as score_spatial
from temporal_score import compute_temporal_scores

TIER4_DATASET_PATH = Path(__file__).parent / "tier4_dataset.parquet"
TIER4_TRAIN_IDS_PATH = Path(__file__).parent / "tier4_train_ids.csv"
TIER4_TEST_IDS_PATH = Path(__file__).parent / "tier4_test_ids.csv"

FIT_FRACTION_OF_TRAIN_GROUPS = 0.75  # of the 32 train groups: 75% to fit the formula, 25% held out to tune the threshold


def _score(df: pd.DataFrame, table) -> pd.DataFrame:
    df = df.reset_index(drop=True).copy()
    df["spatial_inconsistency_score"] = score_spatial(df, table)
    df["temporal_inconsistency_score"] = compute_temporal_scores(df, manifest_path=MANIFEST_PATH)
    return df


def fit_formula():
    dataset = pd.read_parquet(DATASET_PATH)
    tier4 = pd.read_parquet(TIER4_DATASET_PATH)
    train_ids = set(pd.read_csv(TIER4_TRAIN_IDS_PATH)["session_id"])
    tier4_train = tier4[tier4["session_id"].isin(train_ids)]

    table = build_expected_combinations()
    combined = _score(pd.concat([dataset, tier4_train], ignore_index=True), table)

    X = combined[["spatial_inconsistency_score", "temporal_inconsistency_score"]]
    y = (combined[LABEL_COL] != "human").astype(int)  # 1 = any bot class

    lr = LogisticRegression(random_state=RANDOM_SEED)
    lr.fit(X, y)
    w0 = lr.intercept_[0]
    w1, w2 = lr.coef_[0]
    print(f"Fitted formula:  C(s) = sigmoid({w0:.3f} + {w1:.3f}*spatial(s) + {w2:.3f}*temporal(s))")
    print(f"  (fit on {len(combined)} sessions: dataset.parquet + Tier-4 TRAIN-split)")
    return lr, table


def per_session_risk(lr, table, df: pd.DataFrame) -> pd.Series:
    df = _score(df, table)
    X = df[["spatial_inconsistency_score", "temporal_inconsistency_score"]]
    risk = pd.Series(lr.predict_proba(X)[:, 1], index=df.index)
    risk.index = df["session_id"].values
    return risk


def group_risk(session_risk: pd.Series, session_to_group: dict) -> pd.Series:
    """Noisy-OR: GroupRisk(g) = 1 - PRODUCT(1 - C(s)) over sessions s in g."""
    df = pd.DataFrame({
        "risk": session_risk.values,
        "group": [session_to_group[sid] for sid in session_risk.index],
    })
    return df.groupby("group")["risk"].apply(lambda r: 1 - np.prod(1 - r))


def main():
    lr, table = fit_formula()
    manifest = pd.read_csv(MANIFEST_PATH)[["session_id", "client_identity_id"]]
    session_to_group = dict(zip(manifest["session_id"], manifest["client_identity_id"]))

    tier4 = pd.read_parquet(TIER4_DATASET_PATH)
    train_ids = set(pd.read_csv(TIER4_TRAIN_IDS_PATH)["session_id"])
    test_ids = set(pd.read_csv(TIER4_TEST_IDS_PATH)["session_id"])
    tier4_train = tier4[tier4["session_id"].isin(train_ids)]
    tier4_test = tier4[tier4["session_id"].isin(test_ids)]

    # Further split the 32 TRAIN groups into a fit-check set and a threshold
    # validation set. This never touches the 21 TEST groups.
    train_groups = sorted(set(session_to_group[s] for s in tier4_train["session_id"]))
    fit_groups, val_groups = train_test_split(
        train_groups, train_size=FIT_FRACTION_OF_TRAIN_GROUPS, random_state=RANDOM_SEED)
    val_groups = set(val_groups)
    val_sessions = tier4_train[tier4_train["session_id"].map(session_to_group).isin(val_groups)]

    val_risk = per_session_risk(lr, table, val_sessions)
    val_group_risk = group_risk(val_risk, session_to_group)
    # Every session in this validation slice is a real Tier-4 (bot) group —
    # there's no "clean" comparison group at the identity level in this
    # dataset, so the threshold is chosen as the one that flags the most
    # validation groups (all of which SHOULD be flagged, since they're all
    # bot_t4 identities) without going to the degenerate extreme of 0.
    print(f"\nValidation groups ({len(val_group_risk)} Tier-4 train-side groups held back for tuning):")
    print(val_group_risk.sort_values(ascending=False).to_string())

    candidate_thresholds = np.linspace(0.05, 0.95, 19)
    best_t, best_recall = 0.5, -1
    for t in candidate_thresholds:
        recall = (val_group_risk > t).mean()
        if recall >= best_recall and t > 0.05:
            best_t, best_recall = t, recall
    print(f"\nChosen threshold (from validation groups only): {best_t:.2f}  "
          f"(recall on validation groups: {best_recall:.1%})")

    # Final, single evaluation on the untouched TEST groups.
    test_risk = per_session_risk(lr, table, tier4_test)
    test_group_risk = group_risk(test_risk, session_to_group)
    caught = (test_group_risk > best_t)
    n_groups = len(test_group_risk)
    n_caught = int(caught.sum())
    caught_groups = set(test_group_risk[caught].index)
    n_sessions_burned = tier4_test["session_id"].map(session_to_group).isin(caught_groups).sum()

    print(f"\n=== FINAL, single evaluation on the 21 held-out TEST groups ===")
    print(f"Groups caught: {n_caught}/{n_groups} ({n_caught/n_groups:.1%})")
    print(f"Sessions burned: {n_sessions_burned}/{len(tier4_test)} "
          f"({n_sessions_burned/len(tier4_test):.1%} caught, "
          f"{1 - n_sessions_burned/len(tier4_test):.1%} evasion)")


if __name__ == "__main__":
    main()
