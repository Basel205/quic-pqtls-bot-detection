"""
Experiments D1 (spatial) and D2 (spatial + temporal) — the project's core
novel-contribution experiments. Kept in consistency-layer/, not ml/, since
this module (not Basel's baseline/enhanced work) owns D1/D2 per CLAUDE.md's
Team section. Reuses ml/train_utils.py's shared training/evaluation logic —
same model, same split, same metrics as Experiments A/B/C, so results are
directly comparable.

D2 note: runs and reports real numbers, but the temporal-inconsistency score
is currently constant (0) across the whole dataset — see temporal_score.py's
docstring and CLAUDE.md. Not a meaningful test of the temporal hypothesis
until Tier 4 (Phase 5) exists to actually produce fingerprint drift. Reported
here for pipeline completeness, not as a real D1-vs-D2 comparison yet.
"""
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))
from _paths import setup_paths; setup_paths(_ROOT)

from expected_combinations import build_expected_combinations
from spatial_score import score_dataframe as score_spatial
from temporal_score import compute_temporal_scores
from tg_config import DATASET_PATH
from train_utils import train_and_evaluate

import pandas as pd

SPATIAL_SCORES_CSV = Path(__file__).parent / "d1_spatial_scores.csv"
TEMPORAL_SCORES_CSV = Path(__file__).parent / "d2_temporal_scores.csv"


def _ensure_scores_current() -> None:
    """(Re)computes both score CSVs from the current dataset.parquet before training."""
    df = pd.read_parquet(DATASET_PATH)

    table = build_expected_combinations()
    df["spatial_inconsistency_score"] = score_spatial(df, table)
    df[["session_id", "label", "spatial_inconsistency_score"]].to_csv(SPATIAL_SCORES_CSV, index=False)

    df["temporal_inconsistency_score"] = compute_temporal_scores(df)
    df[["session_id", "label", "temporal_inconsistency_score"]].to_csv(TEMPORAL_SCORES_CSV, index=False)


if __name__ == "__main__":
    _ensure_scores_current()

    results = {}
    for experiment in ["D1_spatial", "D2_spatial_temporal"]:
        result = train_and_evaluate(experiment)
        results[experiment] = {k: v for k, v in result.items() if k != "features"}
        print(f"\n=== {experiment} ===")
        print(json.dumps(results[experiment], indent=2))
