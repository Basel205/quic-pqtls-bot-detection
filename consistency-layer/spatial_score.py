"""
Step 5 — spatial-inconsistency scoring function. Feeds Experiment D1.

Given a session's (tls_version, has_pq_keyshare, used_http3, supported_groups
multi-hot, alpn multi-hot) combination, scores how surprising that combination
is relative to the expected_combinations table (human-labeled sessions, lab +
external — see expected_combinations.py).

Score = -log2(probability), i.e. information content in bits. A combination
seen in every human-labeled session scores ~0 (totally expected); a
combination never seen among them scores high (maximally surprising). This is
a standard, interpretable way to turn "how unlikely is this" into a single
number without needing a parametric model — appropriate for a first-pass D1
signal per CLAUDE.md's Step 5 spec.
"""
import math
import sys
from pathlib import Path

import pandas as pd

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))
from _paths import setup_paths; setup_paths(_ROOT)

from expected_combinations import COMBINATION_FIELDS, build_expected_combinations

# Score assigned to a combination never observed among human-labeled sessions
# (lab or external). Equivalent to treating it as rarer than any observed
# combination — one occurrence short of the smallest observed probability —
# rather than an arbitrary large constant.


def _unseen_score(table: pd.DataFrame) -> float:
    total = table["count"].sum()
    smallest_prob = 1.0 / (total + 1)
    return -math.log2(smallest_prob)


def spatial_inconsistency_score(session: dict, table: pd.DataFrame, unseen_score: float | None = None) -> float:
    """
    session: dict or Series with at least the COMBINATION_FIELDS keys
             (e.g. a row from dataset.parquet).
    table:   output of build_expected_combinations().
    Returns a float >= 0; higher = more spatially inconsistent with the
    human-labeled reference distribution.
    """
    if unseen_score is None:
        unseen_score = _unseen_score(table)

    key = tuple(session[f] for f in COMBINATION_FIELDS)
    match = table
    for field, value in zip(COMBINATION_FIELDS, key):
        match = match[match[field] == value]
        if match.empty:
            return unseen_score

    prob = float(match.iloc[0]["probability"])
    return -math.log2(prob)


def score_dataframe(df: pd.DataFrame, table: pd.DataFrame) -> pd.Series:
    """Vectorized-ish batch scorer: returns a Series aligned to df.index."""
    unseen = _unseen_score(table)
    # Merge on the combination key so every row shares work across duplicates
    # rather than re-scanning the table per row.
    merged = df.merge(table[COMBINATION_FIELDS + ["probability"]], on=COMBINATION_FIELDS, how="left")
    scores = merged["probability"].apply(lambda p: unseen if pd.isna(p) else -math.log2(p))
    scores.index = df.index
    return scores


if __name__ == "__main__":
    from tg_config import DATASET_PATH

    table = build_expected_combinations()
    df = pd.read_parquet(DATASET_PATH)
    df["spatial_inconsistency_score"] = score_dataframe(df, table)

    print("Spatial inconsistency score distribution by label:\n")
    print(df.groupby("label")["spatial_inconsistency_score"].describe().to_string())
