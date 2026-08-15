"""
ML pipeline configuration. All training scripts import constants from here.
Change hyperparameters and feature sets here only.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from feature_extraction.feature_schema import (
    EXPERIMENT_A_FEATURES,
    EXPERIMENT_B_FEATURES,
    EXPERIMENT_C_FEATURES,
    LABEL_COL,
    SESSION_ID_COL,
    LABEL_MAP,
    BINARY_LABEL_MAP,
)
from traffic_gen.config import (
    DATASET_PATH,
    RANDOM_SEED,
    TEST_SIZE,
    VAL_SIZE,
    MLFLOW_URI,
)

# ── Experiment definitions ────────────────────────────────────────────────────
EXPERIMENTS = {
    "A_baseline": {
        "features":     EXPERIMENT_A_FEATURES,
        "description":  "Classical TLS features only (JA4 + cipher/extension metadata)",
    },
    "B_enhanced": {
        "features":     EXPERIMENT_B_FEATURES,
        "description":  "All features including PQ key-share, QUIC, and behavioral",
    },
    "C_ablation": {
        "features":     EXPERIMENT_C_FEATURES,
        "description":  "Classical + PQ/QUIC signals, no behavioral timing features",
    },
}

# ── Model hyperparameters ────────────────────────────────────────────────────
XGBOOST_PARAMS = {
    "n_estimators":     300,
    "max_depth":        6,
    "learning_rate":    0.05,
    "subsample":        0.8,
    "colsample_bytree": 0.8,
    "use_label_encoder": False,
    "eval_metric":      "mlogloss",
    "random_state":     RANDOM_SEED,
    "n_jobs":           -1,
}

CATBOOST_PARAMS = {
    "iterations":       300,
    "depth":            6,
    "learning_rate":    0.05,
    "random_seed":      RANDOM_SEED,
    "verbose":          0,
}

# ── Output paths ─────────────────────────────────────────────────────────────
MODEL_REGISTRY = Path(__file__).parent / "model_registry"
RESULTS_DIR    = Path(__file__).parent / "results"
RESULTS_DIR.mkdir(exist_ok=True)
