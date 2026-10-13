import json, sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
from _paths import setup_paths; setup_paths(_ROOT)
sys.path.insert(0, str(_ROOT / 'consistency-layer'))

import numpy as np, pandas as pd, xgboost as xgb, lightgbm as lgb, joblib
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score, roc_auc_score, roc_curve, precision_recall_curve, auc

from ml_config import DATASET_PATH, TEST_SIZE, VAL_SIZE, RANDOM_SEED, MODEL_REGISTRY, RESULTS_DIR
from feature_schema import EXPERIMENT_D2_FEATURES, LABEL_COL, LABEL_MAP, LABEL_MAP_INV, BINARY_LABEL_MAP
from tg_config import MANIFEST_PATH
from expected_combinations import build_expected_combinations
from spatial_score import score_dataframe as score_spatial
from temporal_score import compute_temporal_scores

TIER4_DATASET_PATH = Path(__file__).parent / 'tier4_dataset.parquet'
TIER4_TEST_IDS_PATH = Path(__file__).parent / 'tier4_test_ids.csv'
TIER4_TRAIN_IDS_PATH = Path(__file__).parent / 'tier4_train_ids.csv'

TUNED_XGB_PARAMS = dict(n_estimators=200, max_depth=7, learning_rate=0.1, subsample=1.0, colsample_bytree=0.6, min_child_weight=7, gamma=0.5, eval_metric='mlogloss', random_state=RANDOM_SEED, n_jobs=-1)
TUNED_LGB_PARAMS = dict(n_estimators=200, max_depth=7, learning_rate=0.1, subsample=1.0, colsample_bytree=0.6, min_child_weight=7, random_state=RANDOM_SEED, n_jobs=-1, verbose=-1)

def _load_combined():
    base = pd.read_parquet(DATASET_PATH)
    tier4 = pd.read_parquet(TIER4_DATASET_PATH)
    train_ids = set(pd.read_csv(TIER4_TRAIN_IDS_PATH)['session_id'])
    combined = pd.concat([base, tier4[tier4['session_id'].isin(train_ids)]], ignore_index=True)
    table = build_expected_combinations()
    combined['spatial_inconsistency_score'] = score_spatial(combined, table)
    combined['temporal_inconsistency_score'] = compute_temporal_scores(combined, manifest_path=MANIFEST_PATH)
    return combined

def _load_tier4_test():
    tier4 = pd.read_parquet(TIER4_DATASET_PATH).reset_index(drop=True)
    table = build_expected_combinations()
    tier4['spatial_inconsistency_score'] = score_spatial(tier4, table)
    tier4['temporal_inconsistency_score'] = compute_temporal_scores(tier4, manifest_path=MANIFEST_PATH)
    if TIER4_TEST_IDS_PATH.exists():
        test_ids = set(pd.read_csv(TIER4_TEST_IDS_PATH)['session_id'])
        tier4 = tier4[tier4['session_id'].isin(test_ids)].copy()
    return tier4.reset_index(drop=True)

def _sw(combined, train_idx):
    n4 = (combined[LABEL_COL] == 'bot_t4').sum(); n = len(combined); nc = combined[LABEL_COL].nunique()
    f = (n / nc) / n4 if n4 > 0 else 1.0
    sw = np.where(combined[LABEL_COL] == 'bot_t4', f, 1.0)
    return sw[train_idx]

def _split(X, y):
    Xtr, Xtmp, ytr, ytmp = train_test_split(X, y, test_size=TEST_SIZE+VAL_SIZE, random_state=RANDOM_SEED, stratify=y)
    frac = TEST_SIZE / (TEST_SIZE + VAL_SIZE)
    Xval, Xtest, yval, ytest = train_test_split(Xtmp, ytmp, test_size=frac, random_state=RANDOM_SEED, stratify=ytmp)
    return Xtr, Xval, Xtest, ytr, yval, ytest

def _ev(model, features, tdf):
    return sum(1 for l in [LABEL_MAP_INV[int(p)] for p in model.predict(tdf[features])] if l == 'human') / len(tdf)

def _bot_proba(proba):
    bot_cols = [LABEL_MAP[k] for k in LABEL_MAP if k != 'human']
    return proba[:, bot_cols].sum(axis=1)

def _curves(bp, tdf):
    yb = tdf[LABEL_COL].map(BINARY_LABEL_MAP)
    fp, tp, _ = roc_curve(yb, bp); p, r, _ = precision_recall_curve(yb, bp)
    return {'roc_auc': float(auc(fp, tp)), 'pr_auc': float(auc(r, p))}

def run_d2_tuned(combined, tier4_test):
    print('\n' + '='*70 + '\nD2_tuned: tuned XGBoost + bot_t4 class weighting\n' + '='*70)
    features = EXPERIMENT_D2_FEATURES
    X = combined[features]; y = combined[LABEL_COL].map(LABEL_MAP)
    Xtr, Xval, Xtest, ytr, yval, ytest = _split(X, y)
    sw = _sw(combined, Xtr.index)
    m = xgb.XGBClassifier(**TUNED_XGB_PARAMS); m.fit(Xtr, ytr, sample_weight=sw)
    yp = m.predict(Xtest); yprob = m.predict_proba(Xtest)
    acc = float(accuracy_score(ytest, yp)); f1 = float(f1_score(ytest, yp, average='macro', zero_division=0))
    rauc = float(roc_auc_score(ytest, yprob, multi_class='ovr', average='macro'))
    ev = _ev(m, features, tier4_test)
    c = _curves(_bot_proba(m.predict_proba(tier4_test[features])), tier4_test)
    print(f'  In-dist: acc={acc:.4f} f1={f1:.4f} roc_auc={rauc:.4f}')
    print(f'  Evasion: {ev:.1%}  (was 18.9% baseline)')
    print(f'  Tier-4 ROC-AUC={c["roc_auc"]:.4f}  PR-AUC={c["pr_auc"]:.4f}')
    MODEL_REGISTRY.mkdir(parents=True, exist_ok=True); RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    mp = MODEL_REGISTRY / 'D2_tuned.joblib'; joblib.dump(m, mp)
    metrics = dict(experiment='D2_tuned', description='D2 features XGBoost tuned+weighted', n_features=len(features), n_train=len(Xtr), n_val=len(Xval), n_test=len(Xtest), accuracy=acc, macro_f1=f1, roc_auc_ovr=rauc, tier4_evasion_rate=ev, tier4_n_sessions=len(tier4_test), tier4_binary_roc_auc=c['roc_auc'], tier4_binary_pr_auc=c['pr_auc'], model_path=str(mp))
    json.dump(metrics, open(RESULTS_DIR / 'D2_tuned.json', 'w'), indent=2)
    print('  -> ml/results/D2_tuned.json'); return m, metrics

def run_d2_ensemble(combined, tier4_test):
    print('\n' + '='*70 + '\nD2_ensemble: Soft-vote XGBoost+LightGBM, tuned+weighted\n' + '='*70)
    features = EXPERIMENT_D2_FEATURES
    X = combined[features]; y = combined[LABEL_COL].map(LABEL_MAP)
    Xtr, Xval, Xtest, ytr, yval, ytest = _split(X, y)
    sw = _sw(combined, Xtr.index)
    xm = xgb.XGBClassifier(**TUNED_XGB_PARAMS); xm.fit(Xtr, ytr, sample_weight=sw)
    lm = lgb.LGBMClassifier(**TUNED_LGB_PARAMS); lm.fit(Xtr, ytr, sample_weight=sw)
    avg_test = (xm.predict_proba(Xtest) + lm.predict_proba(Xtest)) / 2
    yp = avg_test.argmax(axis=1)
    acc = float(accuracy_score(ytest, yp)); f1 = float(f1_score(ytest, yp, average='macro', zero_division=0))
    rauc = float(roc_auc_score(ytest, avg_test, multi_class='ovr', average='macro'))
    avg_t4 = (xm.predict_proba(tier4_test[features]) + lm.predict_proba(tier4_test[features])) / 2
    labels = [LABEL_MAP_INV[int(p)] for p in avg_t4.argmax(axis=1)]
    ev = sum(1 for l in labels if l == 'human') / len(labels)
    c = _curves(_bot_proba(avg_t4), tier4_test)
    print(f'  In-dist: acc={acc:.4f} f1={f1:.4f} roc_auc={rauc:.4f}')
    print(f'  Evasion: {ev:.1%}  (was 18.9% baseline)')
    print(f'  Tier-4 ROC-AUC={c["roc_auc"]:.4f}  PR-AUC={c["pr_auc"]:.4f}')
    MODEL_REGISTRY.mkdir(parents=True, exist_ok=True); RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    xp = MODEL_REGISTRY / 'D2_ensemble_xgb.joblib'; lp = MODEL_REGISTRY / 'D2_ensemble_lgb.joblib'
    joblib.dump(xm, xp); joblib.dump(lm, lp)
    metrics = dict(experiment='D2_ensemble', description='Soft-vote XGBoost+LightGBM ensemble on D2 features tuned+weighted', n_features=len(features), n_train=len(Xtr), n_val=len(Xval), n_test=len(Xtest), accuracy=acc, macro_f1=f1, roc_auc_ovr=rauc, tier4_evasion_rate=ev, tier4_n_sessions=len(tier4_test), tier4_binary_roc_auc=c['roc_auc'], tier4_binary_pr_auc=c['pr_auc'], xgb_model_path=str(xp), lgb_model_path=str(lp))
    json.dump(metrics, open(RESULTS_DIR / 'D2_ensemble.json', 'w'), indent=2)
    print('  -> ml/results/D2_ensemble.json'); return (xm, lm), metrics

def main():
    print('Loading data...')
    combined = _load_combined(); tier4_test = _load_tier4_test()
    print(f'Combined: {len(combined)} rows  |  Tier-4 test: {len(tier4_test)} sessions')
    _, m1 = run_d2_tuned(combined, tier4_test)
    _, m2 = run_d2_ensemble(combined, tier4_test)
    print('\n' + '='*70 + '\nSUMMARY -- evasion on held-out Tier-4:\n' + '='*70)
    for n, ev in [('B_enhanced_retrained', 0.581), ('D2_retrained', 0.189), ('D2_class_weighted', 0.149)]:
        print(f'  {n:44s} {ev:.1%}')
    print(f'  {"D2_tuned (new)":44s} {m1["tier4_evasion_rate"]:.1%}')
    print(f'  {"D2_ensemble (new)":44s} {m2["tier4_evasion_rate"]:.1%}')

if __name__ == '__main__':
    main()
