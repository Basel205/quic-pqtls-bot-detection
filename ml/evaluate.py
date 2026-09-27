"""
Formal evaluation report — the piece your original plan called for and this
repo never built. Three things ml/results/*.json don't currently give you:

1. Per-class precision/recall/F1, with bot_t4 broken out specifically —
   "97% accuracy" hides how the model does on the one class you actually
   care about catching.
2. False-positive rate on REAL human sessions. Every metric so far in this
   project has been "did it catch the bot" — nobody has checked "does D2's
   extra sensitivity cause it to flag more real humans as bots than B does."
   That's a real, missing number for a detection system, not busywork.
3. ROC-AUC / PR-AUC for the binary human-vs-bot_t4 framing specifically,
   which is threshold-independent (evasion rate is a single-threshold
   snapshot; AUC tells you whether the ranking is good across all
   thresholds, not just the default one).

Uses the exact same train/test split each experiment was originally trained
with (same seed, same stratify call) by reproducing the split rather than
saving X_test to disk, so this reads the SAME held-out rows the saved
model never trained on — not a fresh, different split.
"""
import sys
from pathlib import Path

import joblib
import pandas as pd
from sklearn.metrics import (
    classification_report, confusion_matrix, roc_auc_score,
    average_precision_score,
)
from sklearn.model_selection import train_test_split

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
from _paths import setup_paths; setup_paths(_ROOT)

from ml_config import EXPERIMENTS, RANDOM_SEED, TEST_SIZE, VAL_SIZE, MODEL_REGISTRY
from train_utils import load_dataset_for_experiment
from feature_schema import LABEL_COL, LABEL_MAP, LABEL_MAP_INV

TIER4_DATASET_PATH = Path(__file__).parent / "tier4_dataset.parquet"
TIER4_TEST_IDS_PATH = Path(__file__).parent / "tier4_test_ids.csv"


def _reproduce_test_split(experiment_name: str):
    """Rebuilds the exact same X_test/y_test train_and_evaluate() used,
    by repeating its split with the same seed — this is the held-out data
    the saved model never saw, not a new split."""
    df = load_dataset_for_experiment(experiment_name)
    features = EXPERIMENTS[experiment_name]["features"]
    X, y = df[features], df[LABEL_COL].map(LABEL_MAP)
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=(TEST_SIZE + VAL_SIZE), random_state=RANDOM_SEED, stratify=y)
    frac = TEST_SIZE / (TEST_SIZE + VAL_SIZE)
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=frac, random_state=RANDOM_SEED, stratify=y_temp)
    return X_test, y_test


def per_class_report(experiment_name: str):
    model = joblib.load(MODEL_REGISTRY / f"{experiment_name}.joblib")
    features = EXPERIMENTS[experiment_name]["features"]
    X_test, y_test = _reproduce_test_split(experiment_name)
    y_pred = model.predict(X_test[features])

    target_names = [LABEL_MAP_INV[i] for i in sorted(set(y_test) | set(y_pred))]
    print(f"\n=== {experiment_name}: per-class report (held-out in-distribution test set, n={len(y_test)}) ===")
    print(classification_report(y_test, y_pred, target_names=target_names, digits=3, zero_division=0))

    # False-positive rate on real human sessions specifically: of the actual
    # human rows in this test split, what fraction got predicted as ANY bot class.
    human_label = LABEL_MAP["human"]
    human_mask = (y_test == human_label)
    if human_mask.sum() > 0:
        fpr = (y_pred[human_mask.to_numpy()] != human_label).mean()
        print(f"False-positive rate on real human sessions: {fpr:.1%} "
              f"({int((y_pred[human_mask.to_numpy()] != human_label).sum())}/{int(human_mask.sum())} "
              f"real humans misclassified as some bot class)")
    return X_test, y_test, y_pred


def binary_human_vs_bot_t4_auc(experiment_name: str, features: list[str]):
    """Combines held-out human rows (from the in-distribution test split)
    with the tier4 evasion test set, and computes ROC-AUC / PR-AUC for
    P(human) as the ranking score against the binary target
    is_human ∈ {0,1}. This is the threshold-independent counterpart to the
    evasion rate, which is a single-threshold (argmax) snapshot."""
    model = joblib.load(MODEL_REGISTRY / f"{experiment_name}.joblib")
    X_test, y_test = _reproduce_test_split(experiment_name)
    human_label = LABEL_MAP["human"]
    human_rows = X_test[(y_test == human_label).to_numpy()]

    if not TIER4_TEST_IDS_PATH.exists():
        print(f"  (skip AUC for {experiment_name} — tier4_test_ids.csv not found)")
        return
    tier4 = pd.read_parquet(TIER4_DATASET_PATH)
    test_ids = set(pd.read_csv(TIER4_TEST_IDS_PATH)["session_id"])
    tier4_test = tier4[tier4["session_id"].isin(test_ids)]

    # tier4_test needs the same engineered features the model expects —
    # reuse whatever's already been computed for it by evasion_test.py's own
    # run (it's cheap to recompute directly here so this script has no
    # ordering dependency on evasion_test.py having just been run).
    if "spatial_inconsistency_score" in features or "temporal_inconsistency_score" in features:
        sys.path.insert(0, str(_ROOT / "consistency-layer"))
        from expected_combinations import build_expected_combinations
        from spatial_score import score_dataframe as score_spatial
        from temporal_score import compute_temporal_scores
        from tg_config import MANIFEST_PATH
        tier4_test = tier4_test.reset_index(drop=True)
        table = build_expected_combinations()
        tier4_test["spatial_inconsistency_score"] = score_spatial(tier4_test, table)
        tier4_test["temporal_inconsistency_score"] = compute_temporal_scores(tier4_test, manifest_path=MANIFEST_PATH)

    bot_rows = tier4_test[features]
    X_combined = pd.concat([human_rows, bot_rows], ignore_index=True)
    y_true = [1] * len(human_rows) + [0] * len(bot_rows)  # 1 = human

    class_list = list(model.classes_)
    human_col = class_list.index(human_label)
    p_human = model.predict_proba(X_combined)[:, human_col]

    auc = roc_auc_score(y_true, p_human)
    ap = average_precision_score(y_true, p_human)
    print(f"{experiment_name:30s} human-vs-bot_t4 ROC-AUC={auc:.4f}  PR-AUC={ap:.4f}  "
          f"(n_human={len(human_rows)}, n_bot_t4={len(bot_rows)})")


if __name__ == "__main__":
    for exp in ["A_baseline", "B_enhanced", "D1_spatial", "D2_spatial_temporal"]:
        per_class_report(exp)

    print("\n=== Binary human-vs-bot_t4 AUC (threshold-independent, complements evasion rate) ===")
    from feature_schema import EXPERIMENT_B_FEATURES, EXPERIMENT_D1_FEATURES, EXPERIMENT_D2_FEATURES
    for exp, feats in [
        ("B_enhanced_retrained", EXPERIMENT_B_FEATURES),
        ("D1_spatial_retrained", EXPERIMENT_D1_FEATURES),
        ("D2_spatial_temporal_retrained", EXPERIMENT_D2_FEATURES),
    ]:
        model_path = MODEL_REGISTRY / f"{exp}.joblib"
        if model_path.exists():
            binary_human_vs_bot_t4_auc(exp, feats)
