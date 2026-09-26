"""
Splits Tier 4 (bot_t4) sessions into a TRAIN portion and a TEST portion, at
the client_identity_id GROUP level — never splitting one identity's sessions
across both sides.

Why group-level, not session-level: D2's temporal score is computed by
comparing a session against its siblings in the same client_identity_id
group (see consistency-layer/temporal_score.py). If sessions from the same
identity ended up on both sides of the split, the "test" score for a held-out
session would partly be derived from sessions the model was trained on —
data leakage that would make the evasion-test result invalid. Splitting by
whole identity groups avoids this by construction.

Run this once before ml/train_retrained.py and before re-running
ml/evasion_test.py. Writes:
  ml/tier4_train_ids.csv  — session_ids to fold into training (~60% of groups)
  ml/tier4_test_ids.csv   — session_ids to hold out for the evasion test (~40%)

Re-running this script reproduces the same split every time (seeded from
ml_config.RANDOM_SEED), so it's safe to re-run if the files are lost.
"""
import sys
from pathlib import Path

import numpy as np
import pandas as pd

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
from _paths import setup_paths; setup_paths(_ROOT)

from ml_config import RANDOM_SEED
from tg_config import MANIFEST_PATH

TIER4_DATASET_PATH = Path(__file__).parent / "tier4_dataset.parquet"
TRAIN_IDS_PATH = Path(__file__).parent / "tier4_train_ids.csv"
TEST_IDS_PATH = Path(__file__).parent / "tier4_test_ids.csv"

TRAIN_FRACTION = 0.6  # fraction of IDENTITY GROUPS (not sessions) put into training


def split_tier4(train_fraction: float = TRAIN_FRACTION, seed: int = RANDOM_SEED) -> tuple[pd.DataFrame, pd.DataFrame]:
    if not TIER4_DATASET_PATH.exists():
        raise FileNotFoundError(
            f"{TIER4_DATASET_PATH} not found — run `python ml/evasion_test.py` once "
            "first (it builds this file from the tier4 pcaps) before splitting it."
        )

    tier4 = pd.read_parquet(TIER4_DATASET_PATH)
    manifest = pd.read_csv(MANIFEST_PATH)[["session_id", "client_identity_id"]]
    tier4 = tier4.merge(manifest, on="session_id", how="left")

    if tier4["client_identity_id"].isna().any():
        missing = tier4[tier4["client_identity_id"].isna()]["session_id"].tolist()
        raise RuntimeError(f"{len(missing)} tier4 session_ids have no client_identity_id in the manifest: {missing[:5]}...")

    groups = tier4["client_identity_id"].unique()
    # np.random.RandomState.shuffle on an array of strings works fine; the
    # ArrowStringArray shuffle warning some pandas versions raise here is
    # cosmetic and doesn't affect correctness — using a plain numpy array
    # of Python strings avoids it entirely.
    groups = np.array(sorted(groups), dtype=object)
    rng = np.random.RandomState(seed)
    order = rng.permutation(len(groups))
    groups = groups[order]

    n_train_groups = int(round(len(groups) * train_fraction))
    train_groups = set(groups[:n_train_groups])
    test_groups = set(groups[n_train_groups:])

    train_df = tier4[tier4["client_identity_id"].isin(train_groups)]
    test_df = tier4[tier4["client_identity_id"].isin(test_groups)]

    train_df[["session_id"]].to_csv(TRAIN_IDS_PATH, index=False)
    test_df[["session_id"]].to_csv(TEST_IDS_PATH, index=False)

    print(f"[split_tier4] {len(groups)} client_identity_id groups -> "
          f"{len(train_groups)} train / {len(test_groups)} test")
    print(f"[split_tier4] {len(train_df)} sessions -> {TRAIN_IDS_PATH}")
    print(f"[split_tier4] {len(test_df)} sessions -> {TEST_IDS_PATH}")

    overlap = train_groups & test_groups
    assert not overlap, f"BUG: {len(overlap)} identity groups ended up on both sides"

    return train_df, test_df


if __name__ == "__main__":
    split_tier4()
