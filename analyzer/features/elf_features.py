"""
ELF static feature extraction for the PodTrace / ConPoint file classifier.

Given a path to a file recovered from a checkpoint (rootfs-diff), produce a
flat dict of named, interpretable features suitable for a gradient-boosted /
random-forest classifier that labels the file malicious vs benign.

Feature groups
--------------
1. byte-level      : size, Shannon entropy, printable ratio, byte histogram
2. ELF structural  : sections/segments, RWX segments, imports, stripped, PIE...
3. import-symbol   : boolean flags for API commonly abused by DDoS bots
4. string / IOC    : counts of URLs, IPs, shell tokens, DDoS/botnet tokens, UPX

`lief` is used for structural/import features when available; the module still
returns byte + string features if lief is missing, so it never hard-fails.
"""
from __future__ import annotations

import math
import re
import hashlib
from collections import Counter
from pathlib import Path
from typing import Dict

try:
    import lief
    lief.logging.disable()
    _HAVE_LIEF = True
except Exception:  # pragma: no cover
    _HAVE_LIEF = False

ELF_MAGIC = b"\x7fELF"

# API frequently seen in flooders / bots / droppers
_SUSPICIOUS_IMPORTS = {
    "socket", "connect", "sendto", "recvfrom", "bind", "listen",
    "fork", "clone", "execve", "execl", "system", "popen",
    "ptrace", "dlopen", "prctl", "setsockopt", "inet_addr",
}

_DDOS_TOKENS = re.compile(
    rb"(mirai|gafgyt|bashlite|tsunami|kaiten|xorddos|botnet|flood|"
    rb"\.stratum|xmrig|hping|slowloris|udpflood|synflood|/dev/watchdog|busybox)",
    re.IGNORECASE,
)
_SHELL_TOKENS = re.compile(
    rb"(wget|curl|tftp|chmod|/bin/sh|/bin/bash|nc |ncat|base64|/tmp/|/dev/shm)",
    re.IGNORECASE,
)
_URL_RE = re.compile(rb"https?://[^\s\"']{4,}", re.IGNORECASE)
_IP_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_UPX_RE = re.compile(rb"UPX!|\$Info: This file is packed", re.IGNORECASE)


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def is_elf(path: str | Path) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(4) == ELF_MAGIC
    except Exception:
        return False


def sha256_of(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _byte_features(data: bytes) -> Dict[str, float]:
    feats: Dict[str, float] = {}
    feats["file_size"] = float(len(data))
    feats["entropy"] = shannon_entropy(data)
    printable = sum(1 for b in data if 32 <= b < 127)
    feats["printable_ratio"] = printable / len(data) if data else 0.0
    # normalized 256-bin byte histogram
    hist = Counter(data)
    total = len(data) or 1
    for i in range(256):
        feats[f"byte_{i:03d}"] = hist.get(i, 0) / total
    return feats


def _string_features(data: bytes) -> Dict[str, float]:
    feats: Dict[str, float] = {}
    feats["n_urls"] = float(len(_URL_RE.findall(data)))
    feats["n_ips"] = float(len(_IP_RE.findall(data)))
    feats["n_shell_tokens"] = float(len(_SHELL_TOKENS.findall(data)))
    feats["n_ddos_tokens"] = float(len(_DDOS_TOKENS.findall(data)))
    feats["has_upx"] = 1.0 if _UPX_RE.search(data) else 0.0
    # longest printable ascii run (droppers embed long b64 blobs / configs)
    runs = re.findall(rb"[\x20-\x7e]{5,}", data)
    feats["max_string_len"] = float(max((len(r) for r in runs), default=0))
    feats["n_strings"] = float(len(runs))
    return feats


def _elf_structural_features(path: str) -> Dict[str, float]:
    feats: Dict[str, float] = {
        "elf_is_64": 0.0, "elf_is_pie": 0.0, "elf_is_stripped": 1.0,
        "elf_n_sections": 0.0, "elf_n_segments": 0.0, "elf_n_rwx_segments": 0.0,
        "elf_n_imported_functions": 0.0, "elf_n_imported_libraries": 0.0,
        "elf_n_dynamic_entries": 0.0, "elf_has_debug": 0.0,
        "elf_section_entropy_mean": 0.0, "elf_section_entropy_max": 0.0,
        "elf_is_dynamic": 0.0,
    }
    for name in _SUSPICIOUS_IMPORTS:
        feats[f"imp_{name}"] = 0.0
    if not _HAVE_LIEF:
        return feats
    try:
        binary = lief.parse(path)
        if binary is None:
            return feats

        feats["elf_is_64"] = 1.0 if binary.header.identity_class == lief.ELF.Header.CLASS.ELF64 else 0.0
        feats["elf_is_pie"] = 1.0 if getattr(binary, "is_pie", False) else 0.0
        feats["elf_n_sections"] = float(len(binary.sections))
        feats["elf_n_segments"] = float(len(binary.segments))
        feats["elf_n_dynamic_entries"] = float(len(binary.dynamic_entries))
        feats["elf_has_debug"] = 1.0 if any(s.name.startswith(".debug") for s in binary.sections) else 0.0

        # RWX segments: raw_flags bits  X=1, W=2, R=4  -> RWX == 7
        rwx = sum(1 for seg in binary.segments if (int(seg.raw_flags) & 0x7) == 0x7)
        feats["elf_n_rwx_segments"] = float(rwx)

        ents = [sec.entropy for sec in binary.sections]
        if ents:
            feats["elf_section_entropy_mean"] = sum(ents) / len(ents)
            feats["elf_section_entropy_max"] = max(ents)

        imported = [f.name for f in binary.imported_functions]
        feats["elf_n_imported_functions"] = float(len(imported))
        feats["elf_n_imported_libraries"] = float(len(binary.libraries))
        feats["elf_is_dynamic"] = 1.0 if len(binary.libraries) > 0 else 0.0
        # symbol table present -> not stripped
        n_syms = len(list(binary.symtab_symbols))
        feats["elf_is_stripped"] = 0.0 if n_syms > 0 else 1.0

        imported_set = set(imported)
        for name in _SUSPICIOUS_IMPORTS:
            feats[f"imp_{name}"] = 1.0 if name in imported_set else 0.0
    except Exception:
        pass
    return feats


def extract_features(path: str | Path, include_histogram: bool = True) -> Dict[str, float]:
    """Return a flat {feature_name: float} dict for one file."""
    path = str(path)
    with open(path, "rb") as fh:
        data = fh.read()

    feats: Dict[str, float] = {}
    byte_feats = _byte_features(data)
    if not include_histogram:
        byte_feats = {k: v for k, v in byte_feats.items() if not k.startswith("byte_")}
    feats.update(byte_feats)
    feats.update(_string_features(data))
    feats.update(_elf_structural_features(path))
    return feats


if __name__ == "__main__":
    import json, sys
    for p in sys.argv[1:]:
        print(p, "elf" if is_elf(p) else "not-elf")
        print(json.dumps(extract_features(p, include_histogram=False), indent=2))
