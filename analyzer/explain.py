"""
SHAP explainability for the file classifier.

Two uses:
  * global : which features drive the model overall  (beeswarm summary plot)
  * local  : for ONE flagged file, which features pushed it toward "malicious"
             -> surfaced in the report so every verdict is explainable, not a
             black box. This is a key research talking point.

Works with tree models (RandomForest / XGBoost / GradientBoosting) via
shap.TreeExplainer, which is exact and fast.

Standalone (global plot):
    python3 explain.py --data datasets --model models/file_clf.joblib --out reports
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict, List

import numpy as np

try:
    import shap
    _HAVE_SHAP = True
except Exception:
    _HAVE_SHAP = False


def make_explainer(model):
    if not _HAVE_SHAP:
        return None
    try:
        return shap.TreeExplainer(model)
    except Exception:
        return None


def _positive_class_sv(shap_values):
    """Normalize shap output to a 2D array of contributions for the malicious class."""
    if isinstance(shap_values, list):          # RF: [class0, class1]
        return np.asarray(shap_values[1])
    arr = np.asarray(shap_values)
    if arr.ndim == 3:                          # (n, features, classes)
        return arr[:, :, 1]
    return arr                                 # XGB binary: (n, features)


def local_explanation(explainer, x_row: List[float], feature_names: List[str],
                      k: int = 6) -> List[Dict]:
    """Top-k features pushing THIS sample toward malicious (signed SHAP)."""
    if explainer is None:
        return []
    try:
        sv = _positive_class_sv(explainer.shap_values(np.asarray([x_row])))[0]
    except Exception:
        return []
    idx = np.argsort(np.abs(sv))[::-1][:k]
    out = []
    for i in idx:
        out.append({"feature": feature_names[i],
                    "value": round(float(x_row[i]), 3),
                    "shap": round(float(sv[i]), 3),
                    "direction": "→ malicious" if sv[i] > 0 else "→ benign"})
    return out


def global_summary(model, X: np.ndarray, feature_names: List[str], out_png: Path):
    if not _HAVE_SHAP:
        print("[!] shap not installed")
        return
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    explainer = make_explainer(model)
    sv = _positive_class_sv(explainer.shap_values(X))
    shap.summary_plot(sv, X, feature_names=feature_names, show=False, max_display=20)
    plt.tight_layout()
    plt.savefig(out_png, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[+] global SHAP summary -> {out_png}")


if __name__ == "__main__":
    import argparse
    import joblib
    import pandas as pd

    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="datasets")
    ap.add_argument("--model", default="models/file_clf.joblib")
    ap.add_argument("--out", default="reports")
    args = ap.parse_args()

    bundle = joblib.load(args.model)
    df = pd.read_parquet(Path(args.data) / "test.parquet")
    feats = bundle["features"]
    X = df[feats].astype(float).values
    out = Path(args.out); out.mkdir(parents=True, exist_ok=True)
    global_summary(bundle["model"], X, feats, out / "shap_summary.png")
