"""
Scorer — wraps a trained model (B_enhanced_retrained by default; D2 needs
spatial/temporal scores which require the expected-combination table and
identity history respectively, both available at proxy-runtime, see
score_d2() below) for real-time use by proxy.py.
"""
import sys
from pathlib import Path

import joblib
import pandas as pd

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
from _paths import setup_paths; setup_paths(_ROOT)
sys.path.insert(0, str(_ROOT / "consistency-layer"))

from ml_config import MODEL_REGISTRY
from feature_schema import EXPERIMENT_B_FEATURES, EXPERIMENT_D2_FEATURES, LABEL_MAP_INV
from expected_combinations import build_expected_combinations
from spatial_score import score_dataframe as score_spatial

_model_B = None
_expected_table = None
_identity_history: dict[str, list[dict]] = {}  # client_identity_id -> recent feature dicts, in-memory only


def _lazy_load():
    global _model_B, _expected_table
    if _model_B is None:
        _model_B = joblib.load(MODEL_REGISTRY / "B_enhanced_retrained.joblib")
        _expected_table = build_expected_combinations()


def score_session(features: dict, client_identity_id: str | None = None) -> dict:
    """Returns {"predicted_label", "p_human", "risk_score", "latency_note"}.
    B_enhanced_retrained is used for the real-time gate (needs only this
    session's features). If client_identity_id is provided and this isn't
    its first observed session, the spatial score (computable from this
    session alone) is also folded in via the Consistency Risk Score formula
    from ml/consistency_risk_score.py — full D2 group-level scoring needs
    that history, which only exists once a return visit happens."""
    _lazy_load()
    df = pd.DataFrame([features])

    pred = _model_B.predict(df[EXPERIMENT_B_FEATURES])[0]
    proba = _model_B.predict_proba(df[EXPERIMENT_B_FEATURES])[0]
    human_idx = list(_model_B.classes_).index(0)  # LABEL_MAP["human"] == 0
    p_human = float(proba[human_idx])

    spatial = float(score_spatial(df, _expected_table).iloc[0])

    if client_identity_id is not None:
        _identity_history.setdefault(client_identity_id, []).append(features)

    return {
        "predicted_label": LABEL_MAP_INV[pred],
        "p_human": p_human,
        "spatial_inconsistency_score": spatial,
        "risk_score": 1 - p_human,
    }
