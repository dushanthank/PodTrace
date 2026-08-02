#!/usr/bin/env python3
"""
Train the command classifier (suspicious vs benign shell commands).

Input CSV: two columns  text,label   (label: 1=malicious, 0=benign)
  * benign commands: normal ops history, NL2Bash corpus, your own shell history
  * malicious commands: Cowrie/honeypot session logs (public), dropper/flood one-liners

Model: TF-IDF (word + char n-grams) -> LogisticRegression. At inference the ML
score is combined with the high-precision rule layer (command_features.rule_score).

Usage:
    python3 train_command_clf.py --csv ../datasets/commands.csv --out ../models
"""
import argparse
import json
import sys
from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from features.command_features import normalize  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default="../datasets/commands.csv")
    ap.add_argument("--out", default="../models")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    df = pd.read_csv(args.csv).dropna(subset=["text", "label"])
    df["norm"] = df["text"].astype(str).map(normalize)
    X_tr, X_te, y_tr, y_te = train_test_split(
        df["norm"], df["label"].astype(int), test_size=0.2,
        stratify=df["label"], random_state=args.seed)

    pipe = Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 4),
                                  min_df=2, max_features=20000)),
        ("clf", LogisticRegression(max_iter=2000, class_weight="balanced")),
    ])
    pipe.fit(X_tr, y_tr)

    proba = pipe.predict_proba(X_te)[:, 1]
    pred = (proba >= 0.5).astype(int)
    roc = roc_auc_score(y_te, proba)
    rep = classification_report(y_te, pred, target_names=["benign", "malicious"],
                                output_dict=True, zero_division=0)
    print(f"[+] command clf ROC-AUC: {roc:.4f}")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    joblib.dump({"pipeline": pipe, "threshold": 0.5}, out / "command_clf.joblib")
    (out / "command_metrics.json").write_text(json.dumps(
        {"roc_auc": float(roc), "report": rep, "n_train": int(len(X_tr))}, indent=2))
    print(f"[done] saved -> {out/'command_clf.joblib'}")


if __name__ == "__main__":
    main()
