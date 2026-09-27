"""
Section 10 — Models, Training Method, Features (MASTER_IMPLEMENTATION_PLAN §10)

Four concrete improvements, all run and reported with real numbers:

  1. LightGBM comparison — same B/D1/D2 feature sets, different model family.
     If D2 still wins by a similar margin, the finding is about the signal,
     not an XGBoost quirk.

  2. Stratified k-fold cross-validation (k=5) on the main dataset — tighter,
     more standard confidence intervals than the 5-seed evasion spread alone.

  3. RandomizedSearchCV hyperparameter search on XGBOOST_PARAMS — the current
     n_estimators=300, max_depth=6, lr=0.05 etc. were hand-picked, never tuned.

  4. Class-weighting test — bot_t4 is 126/1726 rows (~7.3%) in the retrained
     set. Tests XGBoost scale_pos_weight and sklearn oversampling to see if
     bot_t4 recall improves on the Tier-4 evasion test.

Run after the base retrained models exist (B/D1/D2 retrained joblibs present).
"""
import sys
import json
from pathlib import Path

import numpy as np
import pandas as pd
import xgboost as xgb
import lightgbm as lgb
from sklearn.model_selection import (
    train_test_split, StratifiedKFold, cross_validate, RandomizedSearchCV,
)
from sklearn.metrics import f1_score, roc_auc_score, make_scorer
from sklearn.utils import resample

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
from _paths import setup_paths; setup_paths(_ROOT)
sys.path.insert(0, str(_ROOT / "consistency-layer"))

from ml_config import (
    DATASET_PATH, XGBOOST_PARAMS, TEST_SIZE, VAL_SIZE,
    RANDOM_SEED, MODEL_REGISTRY, RESULTS_DIR,
)
from feature_schema import (
    EXPERIMENT_B_FEATURES, EXPERIMENT_D1_FEATURES, EXPERIMENT_D2_FEATURES,
    LABEL_COL, LABEL_MAP, LABEL_MAP_INV,
)
from tg_config import MANIFEST_PATH
from train_utils import load_dataset_for_experiment
from expected_combinations import build_expected_combinations
from spatial_score import score_dataframe as score_spatial
from temporal_score import compute_temporal_scores

TIER4_DATASET_PATH = Path(__file__).parent / "tier4_dataset.parquet"
TIER4_TEST_IDS_PATH = Path(__file__).parent / "tier4_test_ids.csv"
TIER4_TRAIN_IDS_PATH = Path(__file__).parent / "tier4_train_ids.csv"


# ── helpers ──────────────────────────────────────────────────────────────────

def _add_scores(df: pd.DataFrame, table) -> pd.DataFrame:
    df = df.reset_index(drop=True).copy()
    df["spatial_inconsistency_score"] = score_spatial(df, table)
    df["temporal_inconsistency_score"] = compute_temporal_scores(
        df, manifest_path=MANIFEST_PATH)
    return df


def _load_retrained_dataset(table):
    """Same data the *_retrained models were trained on."""
    base = pd.read_parquet(DATASET_PATH)
    tier4 = pd.read_parquet(TIER4_DATASET_PATH)
    train_ids = set(pd.read_csv(TIER4_TRAIN_IDS_PATH)["session_id"])
    tier4_train = tier4[tier4["session_id"].isin(train_ids)]
    combined = pd.concat([base, tier4_train], ignore_index=True)
    return _add_scores(combined, table)


def _evasion_rate(model, features, test_df: pd.DataFrame) -> float:
    pred = model.predict(test_df[features])
    if hasattr(pred[0], "item"):
        labels = [LABEL_MAP_INV[int(p)] for p in pred]
    else:
        labels = [LABEL_MAP_INV[p] for p in pred]
    return sum(1 for l in labels if l == "human") / len(labels)


def _load_tier4_test(table):
    tier4 = pd.read_parquet(TIER4_DATASET_PATH)
    test_ids = set(pd.read_csv(TIER4_TEST_IDS_PATH)["session_id"])
    t4_test = tier4[tier4["session_id"].isin(test_ids)].reset_index(drop=True)
    return _add_scores(t4_test, table)


# ── 1. LightGBM comparison ───────────────────────────────────────────────────

def run_lightgbm_comparison(combined: pd.DataFrame, tier4_test: pd.DataFrame):
    print("\n" + "="*70)
    print("§10.1  LightGBM comparison — same B/D1/D2 feature sets")
    print("="*70)

    lgb_params = dict(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=RANDOM_SEED,
        n_jobs=-1,
        verbose=-1,
    )

    results = {}
    for exp_name, features in [
        ("B_enhanced_retrained", EXPERIMENT_B_FEATURES),
        ("D1_spatial_retrained", EXPERIMENT_D1_FEATURES),
        ("D2_spatial_temporal_retrained", EXPERIMENT_D2_FEATURES),
    ]:
        X = combined[features]
        y = combined[LABEL_COL].map(LABEL_MAP)
        X_train, X_temp, y_train, y_temp = train_test_split(
            X, y, test_size=(TEST_SIZE + VAL_SIZE),
            random_state=RANDOM_SEED, stratify=y)
        frac = TEST_SIZE / (TEST_SIZE + VAL_SIZE)
        X_val, X_test, y_val, y_test = train_test_split(
            X_temp, y_temp, test_size=frac,
            random_state=RANDOM_SEED, stratify=y_temp)

        model = lgb.LGBMClassifier(**lgb_params)
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)
        acc = (y_pred == y_test.to_numpy()).mean()
        f1 = f1_score(y_test, y_pred, average="macro", zero_division=0)

        ev = _evasion_rate(model, features, tier4_test)
        results[exp_name] = {"accuracy": acc, "macro_f1": f1, "evasion_rate": ev}
        print(f"  LightGBM {exp_name:34s}  acc={acc:.1%}  f1={f1:.4f}  "
              f"evasion={ev:.1%}")

    print("\n  XGBoost reference (from existing runs):")
    for name, xgb_ev in [
        ("B_enhanced_retrained", 0.581),
        ("D1_spatial_retrained", 0.595),
        ("D2_spatial_temporal_retrained", 0.189),
    ]:
        lgb_ev = results[name]["evasion_rate"]
        delta = lgb_ev - xgb_ev
        direction = "worse" if delta > 0 else "better"
        print(f"  {name:38s}  XGB={xgb_ev:.1%}  LGB={lgb_ev:.1%}  "
              f"diff={delta:+.1%} ({direction})")
    print("\n  If D2 still wins by a similar margin -> finding is about the")
    print("  signal, not an XGBoost quirk.")
    return results


# ── 2. Stratified k-fold CV ──────────────────────────────────────────────────

def run_kfold_cv(combined: pd.DataFrame):
    print("\n" + "="*70)
    print("§10.2  Stratified 5-fold CV on the retrained combined dataset")
    print("="*70)

    kf = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_SEED)
    scoring = {
        "accuracy": "accuracy",
        "macro_f1": make_scorer(f1_score, average="macro", zero_division=0),
    }

    for exp_name, features in [
        ("B_enhanced_retrained", EXPERIMENT_B_FEATURES),
        ("D2_spatial_temporal_retrained", EXPERIMENT_D2_FEATURES),
    ]:
        X = combined[features]
        y = combined[LABEL_COL].map(LABEL_MAP)
        model = xgb.XGBClassifier(**XGBOOST_PARAMS)
        cv = cross_validate(model, X, y, cv=kf, scoring=scoring, n_jobs=-1)
        acc_m = cv["test_accuracy"].mean()
        acc_s = cv["test_accuracy"].std()
        f1_m = cv["test_macro_f1"].mean()
        f1_s = cv["test_macro_f1"].std()
        print(f"  {exp_name:38s}  acc={acc_m:.3f}±{acc_s:.3f}  "
              f"f1={f1_m:.4f}±{f1_s:.4f}")


# ── 3. RandomizedSearchCV hyperparameter search ──────────────────────────────

def run_hyperparam_search(combined: pd.DataFrame):
    print("\n" + "="*70)
    print("§10.3  RandomizedSearchCV on XGBOOST_PARAMS (D2 features, 20 trials)")
    print("="*70)

    X = combined[EXPERIMENT_D2_FEATURES]
    y = combined[LABEL_COL].map(LABEL_MAP)

    param_dist = {
        "n_estimators":     [100, 200, 300, 400, 500],
        "max_depth":        [3, 4, 5, 6, 7, 8],
        "learning_rate":    [0.01, 0.02, 0.05, 0.1, 0.15],
        "subsample":        [0.6, 0.7, 0.8, 0.9, 1.0],
        "colsample_bytree": [0.6, 0.7, 0.8, 0.9, 1.0],
        "min_child_weight": [1, 3, 5, 7],
        "gamma":            [0, 0.1, 0.2, 0.5],
    }

    base_params = {k: v for k, v in XGBOOST_PARAMS.items()
                   if k not in param_dist and k != "eval_metric"}
    model = xgb.XGBClassifier(**base_params, eval_metric="mlogloss")
    scorer = make_scorer(f1_score, average="macro", zero_division=0)

    search = RandomizedSearchCV(
        model, param_dist,
        n_iter=20,
        scoring=scorer,
        cv=StratifiedKFold(n_splits=3, shuffle=True, random_state=RANDOM_SEED),
        random_state=RANDOM_SEED,
        n_jobs=-1,
        verbose=0,
    )
    search.fit(X, y)

    print(f"  Best CV macro-F1: {search.best_score_:.4f}")
    print(f"  Best params vs current defaults:")
    defaults = {
        "n_estimators": 300, "max_depth": 6, "learning_rate": 0.05,
        "subsample": 0.8, "colsample_bytree": 0.8,
    }
    for k, v in search.best_params_.items():
        default_v = defaults.get(k, "N/A")
        changed = " << CHANGED" if v != default_v else ""
        print(f"    {k:22s} = {str(v):8s}  (was {default_v}){changed}")

    # Save best params for reference
    out = {"best_score": search.best_score_, "best_params": search.best_params_}
    RESULTS_DIR.mkdir(exist_ok=True)
    with open(RESULTS_DIR / "hyperparam_search.json", "w") as f:
        json.dump(out, f, indent=2)
    print(f"  Saved to ml/results/hyperparam_search.json")
    return search.best_params_


# ── 4. Class-weighting test ──────────────────────────────────────────────────

def run_class_weight_test(combined: pd.DataFrame, tier4_test: pd.DataFrame):
    print("\n" + "="*70)
    print("§10.4  Class-weighting for bot_t4 minority (126/1726 rows = 7.3%)")
    print("="*70)

    features = EXPERIMENT_D2_FEATURES
    X_all = combined[features]
    y_all = combined[LABEL_COL].map(LABEL_MAP)
    X_train, X_temp, y_train, y_temp = train_test_split(
        X_all, y_all, test_size=(TEST_SIZE + VAL_SIZE),
        random_state=RANDOM_SEED, stratify=y_all)
    frac = TEST_SIZE / (TEST_SIZE + VAL_SIZE)
    _, X_test, _, y_test = train_test_split(
        X_temp, y_temp, test_size=frac,
        random_state=RANDOM_SEED, stratify=y_temp)

    X_test_t4 = tier4_test[features]

    results_cw = {}

    # baseline (no weighting) — D2_spatial_temporal_retrained already trained
    from joblib import load as jload
    baseline_path = MODEL_REGISTRY / "D2_spatial_temporal_retrained.joblib"
    if baseline_path.exists():
        m0 = jload(baseline_path)
        ev0 = _evasion_rate(m0, features, tier4_test)
        y_pred0 = m0.predict(X_test[features])
        t4_label = LABEL_MAP["bot_t4"]
        t4_mask = (y_test == t4_label)
        t4_recall0 = (y_pred0[t4_mask.to_numpy()] == t4_label).mean() if t4_mask.sum() > 0 else float('nan')
        print(f"  Baseline (no weighting):   evasion={ev0:.1%}  "
              f"bot_t4 recall (in-dist test)={t4_recall0:.1%}")
        results_cw["baseline"] = {"evasion": ev0, "t4_recall_indist": t4_recall0}

    # Method A: scale_pos_weight — XGBoost doesn't directly support
    # per-class weights in multi-class mode via scale_pos_weight, but we can
    # use sample_weight at fit time to upweight bot_t4 training rows.
    n_bot_t4 = (combined[LABEL_COL] == "bot_t4").sum()
    n_total = len(combined)
    # weight each bot_t4 row so its total contribution matches a balanced class
    n_classes = combined[LABEL_COL].nunique()
    target_weight = (n_total / n_classes) / n_bot_t4 if n_bot_t4 > 0 else 1.0
    sample_weights = np.where(
        combined[LABEL_COL] == "bot_t4", target_weight, 1.0
    )
    sw_train = sample_weights[X_train.index]

    params_a = dict(XGBOOST_PARAMS)
    model_a = xgb.XGBClassifier(**params_a)
    model_a.fit(X_train, y_train, sample_weight=sw_train)
    ev_a = _evasion_rate(model_a, features, tier4_test)
    y_pred_a = model_a.predict(X_test[features])
    t4_recall_a = (y_pred_a[t4_mask.to_numpy()] == t4_label).mean() if t4_mask.sum() > 0 else float('nan')
    print(f"  XGBoost sample_weight:     evasion={ev_a:.1%}  "
          f"bot_t4 recall (in-dist test)={t4_recall_a:.1%}  "
          f"(weight={target_weight:.1f}×)")
    results_cw["sample_weight"] = {"evasion": ev_a, "t4_recall_indist": t4_recall_a,
                                    "t4_weight_factor": target_weight}

    # Method B: oversampling bot_t4 training rows to ~20% of training set
    X_tr_bot4 = X_train[y_train == t4_label]
    y_tr_bot4 = y_train[y_train == t4_label]
    target_n = max(int(len(X_train) * 0.20), len(X_tr_bot4))
    X_os, y_os = resample(X_tr_bot4, y_tr_bot4, n_samples=target_n,
                          random_state=RANDOM_SEED, replace=True)
    X_tr_aug = pd.concat([X_train[y_train != t4_label], X_os])
    y_tr_aug = pd.concat([y_train[y_train != t4_label], y_os])

    params_b = dict(XGBOOST_PARAMS)
    model_b = xgb.XGBClassifier(**params_b)
    model_b.fit(X_tr_aug, y_tr_aug)
    ev_b = _evasion_rate(model_b, features, tier4_test)
    y_pred_b = model_b.predict(X_test[features])
    t4_recall_b = (y_pred_b[t4_mask.to_numpy()] == t4_label).mean() if t4_mask.sum() > 0 else float('nan')
    print(f"  Oversampling (bot_t4->20%%): evasion={ev_b:.1%}  "
          f"bot_t4 recall (in-dist test)={t4_recall_b:.1%}  "
          f"(augmented from {len(X_tr_bot4)} to {target_n} rows)")
    results_cw["oversampling"] = {"evasion": ev_b, "t4_recall_indist": t4_recall_b}

    print("\n  Interpretation: lower evasion on Tier-4 test = better recall on")
    print("  the adaptive bot. Check whether in-dist FP rate on real humans worsens.")

    RESULTS_DIR.mkdir(exist_ok=True)
    with open(RESULTS_DIR / "class_weight_test.json", "w") as f:
        json.dump(results_cw, f, indent=2)
    print(f"  Saved to ml/results/class_weight_test.json")


# ── main ─────────────────────────────────────────────────────────────────────

def main():
    print("Loading datasets and computing consistency scores...")
    table = build_expected_combinations()
    combined = _load_retrained_dataset(table)
    tier4_test = _load_tier4_test(table)
    print(f"Combined training set: {len(combined)} rows  |  "
          f"Tier-4 test set: {len(tier4_test)} rows")

    run_lightgbm_comparison(combined, tier4_test)
    run_kfold_cv(combined)
    best_params = run_hyperparam_search(combined)
    run_class_weight_test(combined, tier4_test)

    print("\n" + "="*70)
    print("Section 10 complete. See ml/results/ for saved JSON outputs.")
    print("="*70)


if __name__ == "__main__":
    main()
