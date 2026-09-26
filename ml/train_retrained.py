"""
Trains B_enhanced_retrained, D1_spatial_retrained, and D2_spatial_temporal_retrained
— the same models/features as B_enhanced/D1_spatial/D2_spatial_temporal, but with
the Tier-4 TRAIN-split sessions (see split_tier4.py) folded into training, so the
model actually sees a PQ-present/QUIC-absent example before the evasion test runs.

Run order:
  1. python ml/evasion_test.py            (builds tier4_dataset.parquet if missing)
  2. python ml/split_tier4.py             (writes tier4_train_ids.csv / tier4_test_ids.csv)
  3. python ml/train_retrained.py         (this script)
  4. python ml/evasion_test.py            (re-run — now evaluates all 9 models on the
                                            same held-out tier4 TEST-split sessions)
"""
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
from _paths import setup_paths; setup_paths(_ROOT)

from train_utils import train_and_evaluate

RETRAINED_EXPERIMENTS = [
    "B_enhanced_retrained",
    "D1_spatial_retrained",
    "D2_spatial_temporal_retrained",
]

if __name__ == "__main__":
    for exp in RETRAINED_EXPERIMENTS:
        result = train_and_evaluate(exp)
        summary = {k: v for k, v in result.items() if k != "features"}
        print(f"\n=== {exp} ===")
        print(json.dumps(summary, indent=2))
