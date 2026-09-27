"""
Statistical significance (McNemar's test) for the evasion-test comparison,
plus the actual graphs for the report: evasion-rate bar chart with error
bars (from multi_seed_eval.py's output), ROC curves, and confusion matrices.

McNemar's test is the correct test here (not a t-test): B and D2 are
evaluated on the exact SAME 74 sessions (paired data), and the question is
"do they disagree in a systematically one-sided way," which is exactly what
McNemar's tests for using only the discordant pairs (sessions where one
caught it and the other didn't).
"""
import sys
from pathlib import Path

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, roc_curve, auc

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
from _paths import setup_paths; setup_paths(_ROOT)
sys.path.insert(0, str(_ROOT / "consistency-layer"))

from ml_config import MODEL_REGISTRY
from tg_config import MANIFEST_PATH
from feature_schema import EXPERIMENT_B_FEATURES, EXPERIMENT_D2_FEATURES, LABEL_MAP
from expected_combinations import build_expected_combinations
from spatial_score import score_dataframe as score_spatial
from temporal_score import compute_temporal_scores

TIER4_DATASET_PATH = Path(__file__).parent / "tier4_dataset.parquet"
TIER4_TEST_IDS_PATH = Path(__file__).parent / "tier4_test_ids.csv"
FIGURES_DIR = Path(__file__).parent / "figures"
FIGURES_DIR.mkdir(exist_ok=True)


def mcnemar_test(correct_A: np.ndarray, correct_B: np.ndarray) -> tuple[float, float]:
    """Exact McNemar's test (binomial form, appropriate for small discordant
    counts) on paired binary outcomes (1 = caught the bot, 0 = evaded).
    Returns (statistic_or_n, p_value)."""
    from scipy.stats import binomtest
    # discordant pairs: A right/B wrong (n01) and A wrong/B right (n10)
    n_A_right_B_wrong = int(((correct_A == 1) & (correct_B == 0)).sum())
    n_A_wrong_B_right = int(((correct_A == 0) & (correct_B == 1)).sum())
    n_discordant = n_A_right_B_wrong + n_A_wrong_B_right
    if n_discordant == 0:
        return 0, 1.0
    result = binomtest(min(n_A_right_B_wrong, n_A_wrong_B_right), n_discordant, 0.5)
    return n_discordant, result.pvalue


def load_test_set_with_scores():
    tier4 = pd.read_parquet(TIER4_DATASET_PATH).reset_index(drop=True)
    table = build_expected_combinations()
    tier4["spatial_inconsistency_score"] = score_spatial(tier4, table)
    tier4["temporal_inconsistency_score"] = compute_temporal_scores(tier4, manifest_path=MANIFEST_PATH)
    test_ids = set(pd.read_csv(TIER4_TEST_IDS_PATH)["session_id"])
    return tier4[tier4["session_id"].isin(test_ids)].reset_index(drop=True)


def main():
    df = load_test_set_with_scores()
    model_B = joblib.load(MODEL_REGISTRY / "B_enhanced_retrained.joblib")
    model_D2 = joblib.load(MODEL_REGISTRY / "D2_spatial_temporal_retrained.joblib")

    pred_B = model_B.predict(df[EXPERIMENT_B_FEATURES])
    pred_D2 = model_D2.predict(df[EXPERIMENT_D2_FEATURES])
    human_label = LABEL_MAP["human"]

    correct_B = (pred_B != human_label).astype(int)   # 1 = caught the bot
    correct_D2 = (pred_D2 != human_label).astype(int)

    n_discordant, p_value = mcnemar_test(correct_B, correct_D2)
    print(f"McNemar's test, B_enhanced_retrained vs D2_spatial_temporal_retrained "
          f"({len(df)} paired test sessions):")
    print(f"  discordant pairs: {n_discordant}")
    print(f"  p-value: {p_value:.6f}")
    print(f"  {'SIGNIFICANT at p<0.05 — the difference is not explainable by chance' if p_value < 0.05 else 'NOT significant'}")

    # Confusion matrices (5-class, on the tier4 evasion test — mostly useful
    # to show what non-bot_t4 predictions each model falls back to)
    for name, pred in [("B_enhanced_retrained", pred_B), ("D2_spatial_temporal_retrained", pred_D2)]:
        labels_present = sorted(set(pred) | {LABEL_MAP["bot_t4"], human_label})
        cm = confusion_matrix(df["label"].map(LABEL_MAP), pred, labels=labels_present)
        print(f"\n{name} predictions on the {len(df)} bot_t4 test sessions "
              f"(all true labels are bot_t4={LABEL_MAP['bot_t4']}):")
        inv = {v: k for k, v in LABEL_MAP.items()}
        print("  predicted:", [inv[l] for l in labels_present])
        print("  counts:   ", cm.sum(axis=0).tolist())

    # ROC curves, B vs D2, for the report. df is 100% bot_t4 sessions — need
    # real held-out human rows mixed in, or "label==human" is always false
    # and the curve is degenerate (this bug was caught by sklearn's own
    # "no positive samples" warning on the first run of this script).
    from ml_config import DATASET_PATH, TEST_SIZE, VAL_SIZE, RANDOM_SEED
    from sklearn.model_selection import train_test_split
    from feature_schema import LABEL_COL
    table = build_expected_combinations()
    main_df = pd.read_parquet(DATASET_PATH)
    main_df["spatial_inconsistency_score"] = score_spatial(main_df, table)
    main_df["temporal_inconsistency_score"] = compute_temporal_scores(main_df, manifest_path=MANIFEST_PATH)
    y_all = main_df[LABEL_COL].map(LABEL_MAP)
    _, X_temp, _, y_temp = train_test_split(
        main_df, y_all, test_size=(TEST_SIZE + VAL_SIZE), random_state=RANDOM_SEED, stratify=y_all)
    frac = TEST_SIZE / (TEST_SIZE + VAL_SIZE)
    _, X_test_main, _, y_test_main = train_test_split(
        X_temp, y_temp, test_size=frac, random_state=RANDOM_SEED, stratify=y_temp)
    human_rows = X_test_main[(y_test_main == human_label).to_numpy()]
    roc_df = pd.concat([human_rows, df], ignore_index=True)
    y_is_human = [1] * len(human_rows) + [0] * len(df)

    fig, ax = plt.subplots(figsize=(6, 6))
    for name, model, feats in [("B_enhanced_retrained", model_B, EXPERIMENT_B_FEATURES),
                                 ("D2_spatial_temporal_retrained", model_D2, EXPERIMENT_D2_FEATURES)]:
        p_human = model.predict_proba(roc_df[feats])[:, list(model.classes_).index(human_label)]
        fpr, tpr, _ = roc_curve(y_is_human, p_human)
        roc_auc = auc(fpr, tpr)
        ax.plot(fpr, tpr, label=f"{name} (AUC={roc_auc:.3f})")
    ax.plot([0, 1], [0, 1], "k--", alpha=0.3)
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title("ROC: human vs bot_t4, B vs D2 (retrained)")
    ax.legend()
    fig.tight_layout()
    fig.savefig(FIGURES_DIR / "roc_B_vs_D2.png", dpi=150)
    plt.close(fig)
    print(f"\nsaved -> {FIGURES_DIR / 'roc_B_vs_D2.png'}")

    # Evasion-rate bar chart with error bars, from multi_seed_eval.py's output
    seed_csv = Path(__file__).parent / "results" / "multi_seed_evasion.csv"
    if seed_csv.exists():
        seeds = pd.read_csv(seed_csv)
        models = ["B_enhanced_retrained", "D1_spatial_retrained", "D2_spatial_temporal_retrained"]
        means = [seeds[m].mean() * 100 for m in models]
        stds = [seeds[m].std() * 100 for m in models]
        fig, ax = plt.subplots(figsize=(6, 5))
        ax.bar(models, means, yerr=stds, capsize=8, color=["#1f77b4", "#ff7f0e", "#2ca02c"])
        ax.set_ylabel("Evasion rate (%) — lower is better")
        ax.set_title(f"Evasion rate across {len(seeds)} random seeds (mean ± std)")
        plt.xticks(rotation=15)
        fig.tight_layout()
        fig.savefig(FIGURES_DIR / "evasion_rate_multiseed.png", dpi=150)
        plt.close(fig)
        print(f"saved -> {FIGURES_DIR / 'evasion_rate_multiseed.png'}")


if __name__ == "__main__":
    main()
