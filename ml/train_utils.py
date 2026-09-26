"""
Shared training/evaluation logic for Experiments A/B/C/D1/D2 (ml_config.EXPERIMENTS),
including the *_retrained variants (see ml_config.py + split_tier4.py).
train_baseline.py and train_enhanced.py are thin wrappers around this; D1/D2 are
trained from consistency-layer/train_d1_d2.py since they're owned by the
consistency-scoring module, not Basel's baseline/enhanced work. The *_retrained
variants are trained from ml/train_retrained.py.
"""
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
from _paths import setup_paths; setup_paths(_ROOT)
# consistency-layer/ isn't one of Basel's core dirs so setup_paths() doesn't
# add it — needed here for the retrained-experiment scoring functions below.
sys.path.insert(0, str(_ROOT / "consistency-layer"))

import joblib
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score, roc_auc_score
from sklearn.model_selection import train_test_split
import xgboost as xgb

from ml_config import (
    DATASET_PATH, EXPERIMENTS, LABEL_COL, LABEL_MAP, MODEL_REGISTRY,
    RANDOM_SEED, RESULTS_DIR, TEST_SIZE, VAL_SIZE, XGBOOST_PARAMS,
)
from tg_config import MANIFEST_PATH

CONSISTENCY_LAYER = _ROOT / "consistency-layer"
SPATIAL_SCORES_CSV = CONSISTENCY_LAYER / "d1_spatial_scores.csv"
TEMPORAL_SCORES_CSV = CONSISTENCY_LAYER / "d2_temporal_scores.csv"

TIER4_DATASET_PATH = Path(__file__).parent / "tier4_dataset.parquet"
TIER4_TRAIN_IDS_PATH = Path(__file__).parent / "tier4_train_ids.csv"


def _load_base_dataframe(retrained: bool) -> pd.DataFrame:
    """The 1,600-session dataset.parquet, or that PLUS the Tier-4 train-split
    sessions concatenated in, if this experiment is a *_retrained variant.

    This concatenation is the actual fix for the bug the original *_retrained
    attempt had: previously only the score CSVs were extended with tier4 rows,
    but load_dataset_for_experiment() built its base dataframe from
    dataset.parquet alone and left-merged the scores onto it — so any
    session_id in the score CSV that wasn't already in dataset.parquet was
    silently dropped, and training never actually saw the new tier4 examples.
    Concatenating here, before anything else happens, means every downstream
    step (score computation, the train/val/test split, model.fit) operates on
    a dataframe that genuinely includes them.
    """
    df = pd.read_parquet(DATASET_PATH)
    if not retrained:
        return df

    if not TIER4_TRAIN_IDS_PATH.exists():
        raise FileNotFoundError(
            f"{TIER4_TRAIN_IDS_PATH} not found — run `python ml/split_tier4.py` first."
        )
    if not TIER4_DATASET_PATH.exists():
        raise FileNotFoundError(
            f"{TIER4_DATASET_PATH} not found — run `python ml/evasion_test.py` once "
            "first (it builds this file from the tier4 pcaps)."
        )

    train_ids = set(pd.read_csv(TIER4_TRAIN_IDS_PATH)["session_id"])
    tier4 = pd.read_parquet(TIER4_DATASET_PATH)
    tier4_train = tier4[tier4["session_id"].isin(train_ids)]

    if len(tier4_train) == 0:
        raise RuntimeError(
            "tier4_train_ids.csv matched 0 rows in tier4_dataset.parquet — "
            "did split_tier4.py run against a different tier4_dataset.parquet?"
        )

    return pd.concat([df, tier4_train], ignore_index=True)


def load_dataset_for_experiment(experiment_name: str) -> pd.DataFrame:
    """dataset.parquet (plus Tier-4 train rows for *_retrained experiments),
    joined with D1/D2 engineered scores if this experiment needs them."""
    exp = EXPERIMENTS[experiment_name]
    features = exp["features"]
    retrained = exp.get("retrained", False)

    df = _load_base_dataframe(retrained)

    needs_spatial = "spatial_inconsistency_score" in features
    needs_temporal = "temporal_inconsistency_score" in features

    if retrained and (needs_spatial or needs_temporal):
        # The persisted score CSVs only ever cover the original 1,600-session
        # dataset.parquet. For retrained experiments df now also contains
        # tier4-train rows that aren't in those CSVs, so a merge would drop
        # them exactly like the original bug — compute both scores fresh over
        # the actual combined dataframe instead.
        from expected_combinations import build_expected_combinations
        from spatial_score import score_dataframe as score_spatial
        from temporal_score import compute_temporal_scores

        if needs_spatial:
            table = build_expected_combinations()
            df["spatial_inconsistency_score"] = score_spatial(df, table)
        if needs_temporal:
            df["temporal_inconsistency_score"] = compute_temporal_scores(df, manifest_path=MANIFEST_PATH)
        return df

    if needs_spatial:
        if not SPATIAL_SCORES_CSV.exists():
            raise FileNotFoundError(
                f"{SPATIAL_SCORES_CSV} not found — run consistency-layer/spatial_score.py first."
            )
        spatial = pd.read_csv(SPATIAL_SCORES_CSV)[["session_id", "spatial_inconsistency_score"]]
        df = df.merge(spatial, on="session_id", how="left")

    if needs_temporal:
        if not TEMPORAL_SCORES_CSV.exists():
            raise FileNotFoundError(
                f"{TEMPORAL_SCORES_CSV} not found — run consistency-layer/temporal_score.py first."
            )
        temporal = pd.read_csv(TEMPORAL_SCORES_CSV)[["session_id", "temporal_inconsistency_score"]]
        df = df.merge(temporal, on="session_id", how="left")

    return df


def train_and_evaluate(experiment_name: str) -> dict:
    """
    Trains an XGBoost classifier for the named experiment (per ml_config.EXPERIMENTS),
    evaluates on a held-out test split, saves the model + metrics, and returns metrics.
    """
    if experiment_name not in EXPERIMENTS:
        raise ValueError(f"Unknown experiment {experiment_name!r}. Known: {list(EXPERIMENTS)}")

    exp = EXPERIMENTS[experiment_name]
    features = exp["features"]

    df = load_dataset_for_experiment(experiment_name)
    X = df[features]
    y = df[LABEL_COL].map(LABEL_MAP)

    # Stratified train/val/test split per tg_config's TEST_SIZE/VAL_SIZE (0.15/0.15).
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=(TEST_SIZE + VAL_SIZE), random_state=RANDOM_SEED, stratify=y
    )
    test_fraction_of_temp = TEST_SIZE / (TEST_SIZE + VAL_SIZE)
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=test_fraction_of_temp, random_state=RANDOM_SEED, stratify=y_temp
    )

    model = xgb.XGBClassifier(**XGBOOST_PARAMS)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)

    metrics = {
        "experiment":    experiment_name,
        "description":   exp["description"],
        "n_features":    len(features),
        "features":      features,
        "n_train":       len(X_train),
        "n_val":         len(X_val),
        "n_test":        len(X_test),
        "accuracy":      float(accuracy_score(y_test, y_pred)),
        "macro_f1":      float(f1_score(y_test, y_pred, average="macro")),
        "roc_auc_ovr":   float(roc_auc_score(y_test, y_proba, multi_class="ovr", average="macro")),
    }

    MODEL_REGISTRY.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    model_path = MODEL_REGISTRY / f"{experiment_name}.joblib"
    joblib.dump(model, model_path)
    metrics["model_path"] = str(model_path)

    with open(RESULTS_DIR / f"{experiment_name}.json", "w") as f:
        json.dump(metrics, f, indent=2)

    return metrics


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Train/evaluate one experiment from ml_config.EXPERIMENTS")
    parser.add_argument("experiment", choices=list(EXPERIMENTS.keys()))
    args = parser.parse_args()

    result = train_and_evaluate(args.experiment)
    summary = {k: v for k, v in result.items() if k != "features"}
    print(json.dumps(summary, indent=2))
