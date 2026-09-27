"""
SHAP feature-importance analysis — ml/feature_importance.py was an empty
stub in the original plan; this fills it in. Produces, for each requested
experiment: the mean |SHAP value| ranking (which features actually drive the
model's decisions) and a saved bar-chart PNG.

Confirms independently (via game-theoretic attribution, not "the tree didn't
split on it") what the redundancy analysis already established by other
means: D1's spatial_inconsistency_score should rank near the bottom, D2's
temporal_inconsistency_score should rank meaningfully higher.
"""
import sys
from pathlib import Path

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import shap

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
from _paths import setup_paths; setup_paths(_ROOT)

from ml_config import EXPERIMENTS, MODEL_REGISTRY
from train_utils import load_dataset_for_experiment
from feature_schema import LABEL_COL, LABEL_MAP

FIGURES_DIR = Path(__file__).parent / "figures"
FIGURES_DIR.mkdir(exist_ok=True)


def analyze(experiment_name: str, sample_size: int = 300):
    model_path = MODEL_REGISTRY / f"{experiment_name}.joblib"
    if not model_path.exists():
        print(f"SKIP {experiment_name} — {model_path} not found")
        return

    model = joblib.load(model_path)
    features = EXPERIMENTS[experiment_name]["features"]
    df = load_dataset_for_experiment(experiment_name)
    X = df[features]
    if len(X) > sample_size:
        X = X.sample(sample_size, random_state=42)

    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(X)

    # Multi-class XGBoost via shap.TreeExplainer returns shape
    # (n_samples, n_features, n_classes) in current shap versions (older
    # versions/some model types return a list of per-class (n_samples,
    # n_features) arrays instead) — handle both, and average over samples
    # and classes, NOT features, to get one importance score per feature.
    if isinstance(shap_values, list):
        arr = np.stack(shap_values, axis=-1)  # -> (n_samples, n_features, n_classes)
    else:
        arr = shap_values
    assert arr.shape[1] == len(features), (
        f"expected {len(features)} features in axis 1, got shape {arr.shape} — "
        "SHAP's returned array layout changed; fix the axis assumption above "
        "before trusting this ranking."
    )
    mean_abs = np.abs(arr).mean(axis=(0, 2))  # -> (n_features,), averaged over ALL classes

    # IMPORTANT: averaging over all 5 classes lets ja4_fingerprint_hash (which
    # trivially separates bot_t1/bot_t2 from everyone else via classical
    # fingerprinting — a distinction A_baseline already solves) dominate the
    # ranking, even though it's constant across human/bot_t3/full-profile
    # bot_t4 (verified earlier: identical value for all three). The ranking
    # this project actually cares about is which features matter for the
    # bot_t4-specific decision, so also report that in isolation.
    bot_t4_class_idx = LABEL_MAP["bot_t4"]
    if arr.shape[2] > bot_t4_class_idx:
        mean_abs_bot_t4 = np.abs(arr[:, :, bot_t4_class_idx]).mean(axis=0)
    else:
        mean_abs_bot_t4 = None

    ranking = sorted(zip(features, mean_abs), key=lambda x: -x[1])
    print(f"\n=== {experiment_name} — SHAP mean |value| ranking (averaged over ALL classes) ===")
    for name, val in ranking:
        marker = "  <-- consistency score" if "inconsistency_score" in name else ""
        print(f"  {name:32s} {val:.4f}{marker}")

    if mean_abs_bot_t4 is not None:
        ranking_t4 = sorted(zip(features, mean_abs_bot_t4), key=lambda x: -x[1])
        print(f"\n=== {experiment_name} — SHAP ranking for the bot_t4 DECISION specifically "
              f"(the one this project is actually about) ===")
        for name, val in ranking_t4[:10]:
            marker = "  <-- consistency score" if "inconsistency_score" in name else ""
            print(f"  {name:32s} {val:.4f}{marker}")

    fig, ax = plt.subplots(figsize=(8, max(4, 0.3 * len(ranking))))
    names = [n for n, _ in ranking]
    vals = [v for _, v in ranking]
    colors = ["#d62728" if "inconsistency_score" in n else "#1f77b4" for n in names]
    ax.barh(names[::-1], vals[::-1], color=colors[::-1])
    ax.set_xlabel("mean |SHAP value|")
    ax.set_title(f"{experiment_name} — feature importance (red = consistency score)")
    fig.tight_layout()
    out_path = FIGURES_DIR / f"shap_{experiment_name}.png"
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"  saved -> {out_path}")
    return ranking


if __name__ == "__main__":
    for exp in ["B_enhanced_retrained", "D1_spatial_retrained", "D2_spatial_temporal_retrained"]:
        analyze(exp)
