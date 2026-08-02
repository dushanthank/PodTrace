#!/usr/bin/env python3
"""
Algorithm benchmark for the ELF file classifier.

Trains and compares several ML algorithms under identical stratified
cross-validation so you can defend *why* the chosen model was chosen. Produces:
    reports/benchmark_table.csv      metrics per algorithm
    reports/benchmark_table.md       same, markdown (paste into thesis/slides)
    reports/benchmark_roc.png        ROC curves overlaid
    reports/benchmark_bars.png       ROC-AUC / F1 bar chart

Metrics (5-fold CV, out-of-fold predictions): ROC-AUC, PR-AUC, Accuracy,
Precision, Recall, F1, and mean fit time.

Usage:
    python3 benchmark.py --data ../datasets --out ../reports
"""
import argparse
import time
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import (ExtraTreesClassifier, GradientBoostingClassifier,
                              RandomForestClassifier)
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, average_precision_score, f1_score,
                             precision_score, recall_score, roc_auc_score, roc_curve)
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC

NON_FEATURES = {"label", "sha256"}


def models(seed):
    return {
        "LogisticRegression": make_pipeline(
            StandardScaler(), LogisticRegression(max_iter=2000, class_weight="balanced")),
        "SVM-RBF": make_pipeline(
            StandardScaler(), SVC(probability=True, class_weight="balanced", random_state=seed)),
        "RandomForest": RandomForestClassifier(
            n_estimators=400, class_weight="balanced", n_jobs=4, random_state=seed),
        "ExtraTrees": ExtraTreesClassifier(
            n_estimators=400, class_weight="balanced", n_jobs=4, random_state=seed),
        "GradientBoosting": GradientBoostingClassifier(random_state=seed),
    }
    # XGBoost added below if available


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="../datasets")
    ap.add_argument("--out", default="../reports")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    df = pd.read_parquet(Path(args.data) / "train.parquet")
    feats = [c for c in df.columns if c not in NON_FEATURES]
    X = df[feats].astype(float).values
    y = df["label"].astype(int).values
    print(f"[+] {len(y)} samples, {len(feats)} features, "
          f"{int(y.sum())} malicious / {int((y == 0).sum())} benign")

    algos = models(args.seed)
    try:
        from xgboost import XGBClassifier
        algos["XGBoost"] = XGBClassifier(
            n_estimators=400, max_depth=6, learning_rate=0.05, subsample=0.9,
            colsample_bytree=0.9, eval_metric="logloss", n_jobs=4, random_state=args.seed)
    except Exception:
        print("[!] xgboost not available, skipping")

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=args.seed)
    rows, roc_data = [], {}
    for name, clf in algos.items():
        t0 = time.time()
        proba = cross_val_predict(clf, X, y, cv=cv, method="predict_proba", n_jobs=1)[:, 1]
        dt = time.time() - t0
        pred = (proba >= 0.5).astype(int)
        rows.append({
            "algorithm": name,
            "roc_auc": roc_auc_score(y, proba),
            "pr_auc": average_precision_score(y, proba),
            "accuracy": accuracy_score(y, pred),
            "precision": precision_score(y, pred, zero_division=0),
            "recall": recall_score(y, pred, zero_division=0),
            "f1": f1_score(y, pred, zero_division=0),
            "cv_time_s": round(dt, 2),
        })
        roc_data[name] = roc_curve(y, proba)
        print(f"[cv] {name:18s} ROC-AUC={rows[-1]['roc_auc']:.4f}  "
              f"F1={rows[-1]['f1']:.4f}  ({dt:.1f}s)")

    res = pd.DataFrame(rows).sort_values("roc_auc", ascending=False).reset_index(drop=True)
    out = Path(args.out); out.mkdir(parents=True, exist_ok=True)
    res.to_csv(out / "benchmark_table.csv", index=False)
    try:
        md = res.round(4).to_markdown(index=False)   # needs `tabulate`
    except Exception:
        md = "```\n" + res.round(4).to_string(index=False) + "\n```"
    (out / "benchmark_table.md").write_text(md)
    print("\n" + res.round(4).to_string(index=False))
    print(f"\n[+] best by ROC-AUC: {res.iloc[0]['algorithm']}")

    # ROC overlay
    plt.figure(figsize=(6, 5))
    for name, (fpr, tpr, _) in roc_data.items():
        auc = res.loc[res.algorithm == name, "roc_auc"].values[0]
        plt.plot(fpr, tpr, label=f"{name} (AUC={auc:.3f})")
    plt.plot([0, 1], [0, 1], "--", color="grey")
    plt.xlabel("False Positive Rate"); plt.ylabel("True Positive Rate")
    plt.title("Algorithm comparison — ROC"); plt.legend(fontsize=8)
    plt.savefig(out / "benchmark_roc.png", dpi=150, bbox_inches="tight"); plt.close()

    # bars
    fig, ax = plt.subplots(figsize=(7, 4))
    xpos = np.arange(len(res))
    ax.bar(xpos - 0.2, res.roc_auc, 0.4, label="ROC-AUC")
    ax.bar(xpos + 0.2, res.f1, 0.4, label="F1")
    ax.set_xticks(xpos); ax.set_xticklabels(res.algorithm, rotation=30, ha="right", fontsize=8)
    ax.set_ylim(0, 1.02); ax.legend(); ax.set_title("Algorithm comparison")
    plt.savefig(out / "benchmark_bars.png", dpi=150, bbox_inches="tight"); plt.close()
    print(f"[done] table + plots -> {out}")


if __name__ == "__main__":
    main()
