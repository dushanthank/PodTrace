#!/usr/bin/env python3
"""
Build the labelled feature table for the file classifier.

Walks the benign and malware directories, extracts static ELF features for every
sample, labels them (0=benign, 1=malicious), then writes:
    features.parquet      full feature matrix + label + sha256
    train.parquet / test.parquet   stratified split (test kept for submission)

Usage:
    python3 build_dataset.py \
        --benign ../datasets/benign --malware ../datasets/malware/inert \
        --out ../datasets --test-size 0.2
"""
import argparse
import sys
from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from features.elf_features import extract_features, is_elf, sha256_of  # noqa: E402


def collect(dirpath: Path, label: int, include_hist: bool) -> list[dict]:
    rows = []
    if not dirpath.exists():
        print(f"[!] missing dir {dirpath}")
        return rows
    files = [p for p in dirpath.rglob("*") if p.is_file()]
    print(f"[+] {dirpath}: {len(files)} files")
    for i, fp in enumerate(files, 1):
        try:
            if not is_elf(fp):
                continue
            feats = extract_features(fp, include_histogram=include_hist)
            feats["label"] = label
            feats["sha256"] = sha256_of(fp)
            rows.append(feats)
        except Exception as e:
            print(f"    skip {fp.name}: {e}")
        if i % 200 == 0:
            print(f"    ...{i}/{len(files)}")
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--benign", default="../datasets/benign")
    ap.add_argument("--malware", default="../datasets/malware/inert")
    ap.add_argument("--out", default="../datasets")
    ap.add_argument("--test-size", type=float, default=0.2)
    ap.add_argument("--no-histogram", action="store_true",
                    help="drop the 256 byte-histogram features (smaller, more interpretable)")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--max-benign", type=int, default=0,
                    help="cap the benign class (0 = keep all) to reduce imbalance, "
                         "e.g. --max-benign 300")
    args = ap.parse_args()

    include_hist = not args.no_histogram
    rows = collect(Path(args.benign), 0, include_hist)
    rows += collect(Path(args.malware), 1, include_hist)
    if not rows:
        sys.exit("[!] no samples collected -- run collect_benign.py / collect_malware.py first")

    df = pd.DataFrame(rows).fillna(0.0)
    df = df.drop_duplicates(subset="sha256").reset_index(drop=True)

    if args.max_benign > 0:
        benign = df[df.label == 0]
        if len(benign) > args.max_benign:
            keep = benign.sample(args.max_benign, random_state=args.seed)
            df = pd.concat([keep, df[df.label == 1]]).reset_index(drop=True)
            print(f"[+] capped benign to {args.max_benign} to reduce imbalance")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    df.to_parquet(out / "features.parquet", index=False)

    n_pos = int(df.label.sum())
    print(f"[+] dataset: {len(df)} samples  ({n_pos} malicious / {len(df) - n_pos} benign)")
    print(f"[+] feature columns: {df.shape[1] - 2}")

    if df.label.nunique() < 2 or n_pos == 0 or n_pos == len(df):
        which = "MALICIOUS" if n_pos == 0 else "BENIGN"
        sys.exit(
            f"\n[!] dataset has only ONE class — cannot train.\n"
            f"    {which} samples are missing (malware dir: {args.malware}).\n"
            f"    Add ELF malware to that folder, then re-run. Options:\n"
            f"      * real:      download ELF samples from https://bazaar.abuse.ch "
            f"(browse, unzip password 'infected') into {args.malware}\n"
            f"      * real API:  python3 data/collect_malware.py --keep-inert-file "
            f"(needs MB_API_KEY)\n"
            f"      * synthetic: python3 data/make_synthetic.py --out {args.out} --n 300\n")

    train_df, test_df = train_test_split(
        df, test_size=args.test_size, stratify=df.label, random_state=args.seed)
    train_df.to_parquet(out / "train.parquet", index=False)
    test_df.to_parquet(out / "test.parquet", index=False)
    print(f"[done] train={len(train_df)}  test={len(test_df)} -> {out}")


if __name__ == "__main__":
    main()
