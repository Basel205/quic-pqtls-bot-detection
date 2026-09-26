"""
Shared training/evaluation logic for Experiments A/B/C/D1/D2 (ml_config.EXPERIMENTS).
train_baseline.py and train_enhanced.py are thin wrappers around this; D1/D2 are
trained from consistency-layer/train_d1_d2.py since they're owned by the
consistency-scoring module, not Basel's baseline/enhanced work.
"""
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
from _paths import setup_paths; setup_paths(_ROOT)

import joblib
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score, roc_auc_score
from sklearn.model_selection import train_test_split
import xgboost as xgb

from ml_config import (
    DATASET_PATH, EXPERIMENTS, LABEL_COL, LABEL_MAP, MODEL_REGISTRY,
    RANDOM_SEED, RESULTS_DIR, TEST_SIZE, VAL_SIZE, XGBOOST_PARAMS,
)

CONSISTENCY_LAYER = _ROOT / "consistency-layer"
SPATIAL_SCORES_CSV = CONSISTENCY_LAYER / "d1_spatial_scores.csv"
TEMPORAL_SCORES_CSV = CONSISTENCY_LAYER / "d2_temporal_scores.csv"


TIER4_TRAIN_IDS = Path(__file__).parent / "tier4_train_ids.csv"
TIER4_DATASET_PATH = Path(__file__).parent / "tier4_dataset.parquet"


def load_dataset_for_experiment(
    experiment_name: str,
    include_tier4_train: bool = False,
) -> pd.DataFrame:
    """
    Loads dataset.parquet and optionally concatenates the Tier-4 training
    sessions (those designated by split_tier4.py) before joining in D1/D2
    consistency scores.

    include_tier4_train=True is used by the retrained arms (B_enhanced_retrained,
    D1_spatial_retrained, D2_spatial_temporal_retrained). ALL THREE retrained
    arms must pass the same flag so they train on identical data — the only
    variable between them is the feature set, which is what makes their
    evasion-rate comparison valid.

    Bug fix: previously this function started from dataset.parquet and did a
    LEFT merge onto it, which silently dropped any Tier-4 rows added to the
    score CSVs — the left merge only adds columns, never new rows. Now we
    concatenate first, THEN merge scores onto the full combined frame.
    """
    df = pd.read_parquet(DATASET_PATH)

    if include_tier4_train:
        if not TIER4_TRAIN_IDS.exists():
            raise FileNotFoundError(
                f"{TIER4_TRAIN_IDS} not found — run ml/split_tier4.py first."
            )
        if not TIER4_DATASET_PATH.exists():
            raise FileNotFoundError(
                f"{TIER4_DATASET_PATH} not found — run ml/evasion_test.py first "
                "to build tier4_dataset.parquet from pcaps."
            )
        train_ids = set(pd.read_csv(TIER4_TRAIN_IDS)["session_id"].tolist())
        t4_df = pd.read_parquet(TIER4_DATASET_PATH)
        t4_train = t4_df[t4_df["session_id"].isin(train_ids)].copy()
        if len(t4_train) == 0:
            raise RuntimeError(
                "No Tier-4 training sessions found in tier4_dataset.parquet — "
                "check that tier4_train_ids.csv session_ids match tier4_dataset.parquet."
            )
        print(f"[train_utils] Appending {len(t4_train)} Tier-4 train sessions to {len(df)} base sessions.")
        df = pd.concat([df, t4_train], ignore_index=True)

    features = EXPERIMENTS[experiment_name]["features"]

    if "spatial_inconsistency_score" in features:
        if not SPATIAL_SCORES_CSV.exists():
            raise FileNotFoundError(
                f"{SPATIAL_SCORES_CSV} not found — run consistency-layer/train_d1_d2.py first."
            )
        spatial = pd.read_csv(SPATIAL_SCORES_CSV)[["session_id", "spatial_inconsistency_score"]]
        df = df.merge(spatial, on="session_id", how="left")

    if "temporal_inconsistency_score" in features:
        if not TEMPORAL_SCORES_CSV.exists():
            raise FileNotFoundError(
                f"{TEMPORAL_SCORES_CSV} not found — run consistency-layer/train_d1_d2.py first."
            )
        temporal = pd.read_csv(TEMPORAL_SCORES_CSV)[["session_id", "temporal_inconsistency_score"]]
        df = df.merge(temporal, on="session_id", how="left")

    return df



def train_and_evaluate(experiment_name: str) -> dict:
    """
    Trains an XGBoost classifier for the named experiment (per ml_config.EXPERIMENTS),
    evaluates on a held-out test split, saves the model + metrics, and returns metrics.

    For the three *_retrained experiments, automatically enables Tier-4 training data
    inclusion so all three train on an identical combined dataset — the only variable
    between them is the feature set, making their evasion-rate comparison valid.
    """
    if experiment_name not in EXPERIMENTS:
        raise ValueError(f"Unknown experiment {experiment_name!r}. Known: {list(EXPERIMENTS)}")

    exp = EXPERIMENTS[experiment_name]
    features = exp["features"]

    # Retrained arms always include Tier-4 train data — all three must use the
    # same flag so the comparison between them is valid (same data, different features).
    include_tier4_train = experiment_name.endswith("_retrained")
    df = load_dataset_for_experiment(experiment_name, include_tier4_train=include_tier4_train)
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

    n_f = len(features)
    metrics = {
        "experiment":    experiment_name,
        "description":   exp["description"],
        "n_features":    n_f,
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
