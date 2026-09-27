"""
ML pipeline configuration. All training scripts import constants from here.
Change hyperparameters and feature sets here only.
"""
import sys
from pathlib import Path
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
from _paths import setup_paths; setup_paths(_ROOT)

from feature_schema import (
    EXPERIMENT_A_FEATURES,
    EXPERIMENT_B_FEATURES,
    EXPERIMENT_C_FEATURES,
    EXPERIMENT_D1_FEATURES,
    EXPERIMENT_D2_FEATURES,
    EXPERIMENT_SPATIAL_ONLY_FEATURES,
    EXPERIMENT_FULL_CONSISTENCY_FEATURES,
    EXPERIMENT_PQ_ONLY_FEATURES,
    EXPERIMENT_QUIC_ONLY_FEATURES,
    EXPERIMENT_TIMING_ONLY_FEATURES,
    LABEL_COL,
    SESSION_ID_COL,
    LABEL_MAP,
    BINARY_LABEL_MAP,
)
from tg_config import (
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
    "D1_spatial": {
        "features":     EXPERIMENT_D1_FEATURES,
        "description":  "B + spatial-inconsistency score (consistency-layer/spatial_score.py)",
    },
    "D2_spatial_temporal": {
        "features":     EXPERIMENT_D2_FEATURES,
        "description":  (
            "D1 + temporal-inconsistency score (consistency-layer/temporal_score.py). "
            "NOTE: temporal score is currently constant (0) across the whole dataset — "
            "tiers 1-3's traffic generators are deterministic, so there's no fingerprint "
            "drift across repeat-visit sessions to detect yet. This experiment is wired up "
            "and runnable but not a meaningful test of the temporal hypothesis until "
            "Tier 4 (Phase 5's adaptive evasion bot) exists. See CLAUDE.md."
        ),
    },
    "Ablation_spatial_only": {
        "features":     EXPERIMENT_SPATIAL_ONLY_FEATURES,
        "description":  "Ablation Study: Classical + spatial-inconsistency score only (no PQ/QUIC/timing)",
    },
    "Ablation_full_consistency": {
        "features":     EXPERIMENT_FULL_CONSISTENCY_FEATURES,
        "description":  "Ablation Study: Classical + spatial + temporal-inconsistency scores (no PQ/QUIC/timing)",
    },
    "PQ_only": {
        "features":     EXPERIMENT_PQ_ONLY_FEATURES,
        "description":  "Signal-isolation arm: Classical + PQ key-share presence/length only",
    },
    "QUIC_only": {
        "features":     EXPERIMENT_QUIC_ONLY_FEATURES,
        "description":  "Signal-isolation arm: Classical + QUIC transport signals only",
    },
    "Timing_only": {
        "features":     EXPERIMENT_TIMING_ONLY_FEATURES,
        "description":  "Signal-isolation arm: Classical + behavioral timing signals only",
    },

    # ── Retrained variants (Phase 5 fix) ────────────────────────────────────
    # Same feature sets as B_enhanced/D1_spatial/D2_spatial_temporal, but
    # trained on dataset.parquet PLUS the Tier-4 TRAIN-split sessions (see
    # ml/split_tier4.py). Kept as separate experiment names, not overwrites,
    # so the original frozen results stay intact for the before/after
    # comparison table. The "retrained" flag is what train_utils.py's
    # load_dataset_for_experiment() checks to fold in the tier4 rows.
    "B_enhanced_retrained": {
        "features":     EXPERIMENT_B_FEATURES,
        "description":  "B_enhanced retrained with Tier-4 TRAIN-split sessions folded into training",
        "retrained":    True,
    },
    "D1_spatial_retrained": {
        "features":     EXPERIMENT_D1_FEATURES,
        "description":  "D1_spatial retrained with Tier-4 TRAIN-split sessions folded into training",
        "retrained":    True,
    },
    "D2_spatial_temporal_retrained": {
        "features":     EXPERIMENT_D2_FEATURES,
        "description":  (
            "D2_spatial_temporal retrained with Tier-4 TRAIN-split sessions folded into "
            "training. This is the first time temporal_inconsistency_score is non-constant "
            "for ANY training row — Tier 4 mixes 'full' and 'degraded' profile sessions "
            "within the same client_identity_id group, which is what gives D2 something "
            "real to learn from. See ml/group_level_eval.py for the evaluation that isolates "
            "this signal from B_enhanced_retrained's per-session ceiling."
        ),
        "retrained":    True,
    },
}

# ── Model hyperparameters ────────────────────────────────────────────────────
XGBOOST_PARAMS = {
    "n_estimators":     300,
    "max_depth":        6,
    "learning_rate":    0.05,
    "subsample":        0.8,
    "colsample_bytree": 0.8,
    # use_label_encoder removed in xgboost>=1.6 (pinned version is 2.1.0) — passing it
    # raises TypeError on XGBClassifier(); dropped rather than left as dead config.
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
