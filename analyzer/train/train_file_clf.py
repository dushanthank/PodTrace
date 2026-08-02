#!/usr/bin/env python3
"""
Train the ELF file classifier (malicious vs benign).

Trains XGBoost and RandomForest, picks the best by cross-validated ROC-AUC,
and saves the fitted model plus the exact feature order and metadata so the
inference service reproduces training-time feature construction exactly.

Usage:
    python3 train_file_clf.py --data ../datasets --out ../models
Outputs:
    ../models/file_clf.joblib     {model, features, model_name, threshold}
    ../models/train_metrics.json
"""
import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, cross_val_score
from xgboost import XGBClassifier

NON_FEATURES = {"label", "sha256"}


def load_xy(path: Path):
    df = pd.read_parquet(path)
    feats = [c for c in df.columns if c not in NON_FEATURES]
    X = df[feats].astype(float).values
    y = df["label"].astype(int).values
    return X, y, feats


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="../datasets")
    ap.add_argument("--out", default="../models")
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    data = Path(args.data)
    X, y, feats = load_xy(data / "train.parquet")
    print(f"[+] train: {X.shape[0]} samples, {X.shape[1]} features, "
          f"{int(y.sum())} malicious / {int((y == 0).sum())} benign")

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=args.seed)
    candidates = {
        "xgboost": XGBClassifier(
            n_estimators=400, max_depth=6, learning_rate=0.05,
            subsample=0.9, colsample_bytree=0.9, eval_metric="logloss",
            n_jobs=4, random_state=args.seed),
        "random_forest": RandomForestClassifier(
            n_estimators=500, max_depth=None, n_jobs=4,
            class_weight="balanced", random_state=args.seed),
    }

    results = {}
    for name, clf in candidates.items():
        scores = cross_val_score(clf, X, y, cv=cv, scoring="roc_auc", n_jobs=1)
        results[name] = {"cv_roc_auc_mean": float(scores.mean()),
                         "cv_roc_auc_std": float(scores.std())}
        print(f"[cv] {name}: ROC-AUC {scores.mean():.4f} +/- {scores.std():.4f}")

    best_name = max(results, key=lambda k: results[k]["cv_roc_auc_mean"])
    best = candidates[best_name].fit(X, y)
    print(f"[+] best model: {best_name}")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": best, "features": feats, "model_name": best_name,
                 "threshold": args.threshold}, out / "file_clf.joblib")

    # feature importances for the report / thesis
    importances = {}
    if hasattr(best, "feature_importances_"):
        importances = dict(sorted(
            zip(feats, best.feature_importances_.tolist()),
            key=lambda kv: kv[1], reverse=True)[:25])

    (out / "train_metrics.json").write_text(json.dumps(
        {"cv": results, "best_model": best_name,
         "n_train": int(X.shape[0]), "n_features": int(X.shape[1]),
         "top_features": importances}, indent=2))
    print(f"[done] saved -> {out/'file_clf.joblib'}")


if __name__ == "__main__":
    main()
