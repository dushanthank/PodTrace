#!/usr/bin/env python3
"""
Evaluate the trained file classifier on the held-out test set and emit the
metrics + plots you can put straight into a report/thesis.

Usage:
    python3 evaluate.py --data ../datasets --model ../models/file_clf.joblib --out ../reports
Outputs:
    ../reports/eval_metrics.json          ROC-AUC, PR-AUC, precision/recall/F1, confusion
    ../reports/roc_curve.png, pr_curve.png, confusion_matrix.png
"""
import argparse
import json
from pathlib import Path

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import (ConfusionMatrixDisplay, auc, average_precision_score,
                             classification_report, confusion_matrix,
                             precision_recall_curve, roc_auc_score, roc_curve)

NON_FEATURES = {"label", "sha256"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="../datasets")
    ap.add_argument("--model", default="../models/file_clf.joblib")
    ap.add_argument("--out", default="../reports")
    args = ap.parse_args()

    bundle = joblib.load(args.model)
    model, feats, thr = bundle["model"], bundle["features"], bundle["threshold"]

    df = pd.read_parquet(Path(args.data) / "test.parquet")
    X = df[feats].astype(float).values
    y = df["label"].astype(int).values
    proba = model.predict_proba(X)[:, 1]
    pred = (proba >= thr).astype(int)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    roc = roc_auc_score(y, proba)
    pr = average_precision_score(y, proba)
    cm = confusion_matrix(y, pred).tolist()
    report = classification_report(y, pred, target_names=["benign", "malicious"],
                                   output_dict=True, zero_division=0)
    metrics = {"model_name": bundle["model_name"], "n_test": int(len(y)),
               "roc_auc": float(roc), "pr_auc": float(pr),
               "threshold": thr, "confusion_matrix": cm,
               "classification_report": report}
    (out / "eval_metrics.json").write_text(json.dumps(metrics, indent=2))
    print(json.dumps({k: metrics[k] for k in ("roc_auc", "pr_auc", "confusion_matrix")}, indent=2))

    # ROC
    fpr, tpr, _ = roc_curve(y, proba)
    plt.figure(); plt.plot(fpr, tpr, label=f"AUC={roc:.3f}")
    plt.plot([0, 1], [0, 1], "--", color="grey")
    plt.xlabel("False Positive Rate"); plt.ylabel("True Positive Rate")
    plt.title("ROC — ELF malware classifier"); plt.legend()
    plt.savefig(out / "roc_curve.png", dpi=150, bbox_inches="tight"); plt.close()

    # PR
    prec, rec, _ = precision_recall_curve(y, proba)
    plt.figure(); plt.plot(rec, prec, label=f"AP={pr:.3f}")
    plt.xlabel("Recall"); plt.ylabel("Precision")
    plt.title("Precision-Recall"); plt.legend()
    plt.savefig(out / "pr_curve.png", dpi=150, bbox_inches="tight"); plt.close()

    # Confusion
    ConfusionMatrixDisplay(confusion_matrix(y, pred),
                           display_labels=["benign", "malicious"]).plot(cmap="Blues")
    plt.title("Confusion matrix")
    plt.savefig(out / "confusion_matrix.png", dpi=150, bbox_inches="tight"); plt.close()

    print(f"[done] metrics + plots -> {out}")


if __name__ == "__main__":
    main()
