"""
Train the three retrained arms (B, D1, D2) on the combined dataset
(Tiers 1-3 + Tier-4 training groups from ml/split_tier4.py).

Run after:
    python ml/split_tier4.py
    python consistency-layer/train_d1_d2.py   (recomputes scores on combined data)

Then run:
    python ml/evasion_test.py
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


def main() -> None:
    print("=" * 60)
    print("Training retrained arms on combined data (Tiers 1-3 + Tier-4 train groups)")
    print("=" * 60)

    all_results = {}
    for exp in RETRAINED_EXPERIMENTS:
        print(f"\n--- {exp} ---")
        result = train_and_evaluate(exp)
        summary = {k: v for k, v in result.items() if k != "features"}
        all_results[exp] = summary
        print(json.dumps(summary, indent=2))

    print("\n" + "=" * 60)
    print("All retrained arms complete.")
    print("Next step: python ml/evasion_test.py")
    print("=" * 60)


if __name__ == "__main__":
    main()
