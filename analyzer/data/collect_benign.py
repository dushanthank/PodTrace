#!/usr/bin/env python3
"""
Collect BENIGN ELF binaries — the "safe" class for the file classifier.

Two sources (auto-detected):

  * container images  (docker / podman / nerdctl)  -- export a clean base image's
    filesystem and harvest its executables. Best representation of pod files, but
    needs a container engine that supports `export`.

  * the HOST filesystem (--source host)            -- harvest real ELF binaries from
    /usr/bin, /bin, /usr/sbin, /lib, ... . Needs NO container engine, so this is the
    right choice on a containerd-only node (no docker). These are ordinary, benign
    Linux programs (coreutils, etc.) and make a perfectly good benign corpus.

Usage:
    # containerd node (no docker) -> harvest from the host:
    python3 collect_benign.py --source host --out ../datasets/benign

    # docker/podman available:
    python3 collect_benign.py --out ../datasets/benign
    python3 collect_benign.py --source auto --images nginx:latest ubuntu:24.04

Output:
    <out>/<sha256>.elf              deduplicated benign binaries
    <out>/manifest_benign.csv       sha256,source,orig_path,size
"""
import argparse
import csv
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from features.elf_features import is_elf, sha256_of  # noqa: E402

DEFAULT_IMAGES = [
    "nginx:latest", "ubuntu:24.04", "debian:12-slim",
    "alpine:3.20", "python:3.12-slim", "busybox:latest",
    "redis:7", "httpd:2.4",
]
HOST_DIRS = ["/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/lib", "/lib",
             "/usr/libexec", "/usr/local/bin"]


def detect_engine():
    for eng in ("docker", "podman", "nerdctl"):
        if shutil.which(eng):
            return eng
    return None


def _keep(fp: Path, out: Path, source: str, orig: str, seen: set, rows: list) -> bool:
    try:
        if fp.stat().st_size < 512 or fp.is_symlink() or not is_elf(fp):
            return False
        digest = sha256_of(fp)
        if digest in seen:
            return False
        seen.add(digest)
        shutil.copy(fp, out / f"{digest}.elf")
        rows.append([digest, source, orig, fp.stat().st_size])
        return True
    except Exception:
        return False


def harvest_host(out: Path, dirs, limit: int, seen: set, rows: list):
    for d in dirs:
        if not os.path.isdir(d):
            continue
        count = 0
        for root, _, files in os.walk(d):
            for name in files:
                if count >= limit:
                    break
                fp = Path(root) / name
                if _keep(fp, out, f"host:{d}", str(fp), seen, rows):
                    count += 1
        print(f"[+] {d}: collected {count} unique ELF binaries")


def export_image(image: str, engine: str, workdir: Path) -> Path:
    print(f"[+] pulling {image}")
    subprocess.run([engine, "pull", image], check=True)
    cid = subprocess.check_output([engine, "create", image]).decode().strip()
    tar_path = workdir / "fs.tar"
    print(f"[+] exporting {image} ({cid[:12]})")
    with open(tar_path, "wb") as fh:
        subprocess.run([engine, "export", cid], stdout=fh, check=True)
    subprocess.run([engine, "rm", cid], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    extract_dir = workdir / "rootfs"
    extract_dir.mkdir(exist_ok=True)
    with tarfile.open(tar_path) as tf:
        for m in tf.getmembers():
            if m.isfile() and not m.issym() and not m.islnk():
                try:
                    tf.extract(m, extract_dir, filter="data")
                except Exception:
                    pass
    return extract_dir


def harvest_images(out: Path, images, engine: str, limit: int, seen: set, rows: list):
    for image in images:
        with tempfile.TemporaryDirectory() as td:
            try:
                rootfs = export_image(image, engine, Path(td))
            except subprocess.CalledProcessError as e:
                print(f"[!] skipping {image}: {e}")
                continue
            count = 0
            for root, _, files in os.walk(rootfs):
                for name in files:
                    if count >= limit:
                        break
                    fp = Path(root) / name
                    orig = "/" + str(fp.relative_to(rootfs))
                    if _keep(fp, out, image, orig, seen, rows):
                        count += 1
            print(f"[+] {image}: collected {count} unique ELF binaries")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="../datasets/benign")
    ap.add_argument("--source", default="auto",
                    choices=["auto", "host", "docker", "podman", "nerdctl"],
                    help="'host' needs no container engine (use on containerd nodes)")
    ap.add_argument("--images", nargs="*", default=DEFAULT_IMAGES)
    ap.add_argument("--dirs", nargs="*", default=HOST_DIRS)
    ap.add_argument("--max-per-source", type=int, default=400)
    args = ap.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    seen, rows = set(), []

    source = args.source
    if source == "auto":
        eng = detect_engine()
        source = eng if eng else "host"
        print(f"[i] auto source -> {source}"
              + ("" if eng else " (no container engine found; harvesting host)"))

    if source == "host":
        harvest_host(out, args.dirs, args.max_per_source, seen, rows)
    else:
        harvest_images(out, args.images, source, args.max_per_source, seen, rows)

    manifest = out / "manifest_benign.csv"
    with open(manifest, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["sha256", "source", "orig_path", "size"])
        w.writerows(rows)
    print(f"[done] {len(rows)} benign binaries -> {out}  (manifest: {manifest})")
    if len(rows) < 50:
        print("[!] few samples collected — add more --dirs or --images for a better model")


if __name__ == "__main__":
    main()
