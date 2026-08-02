"""
Extra memory-forensic artifacts recovered from a CRIU checkpoint.

These are the artifacts that ONLY exist in the pod's memory and are lost on crash —
the justification for capturing a memory image at all. None of these use ML; they
are recovered by parsing the CRIU images with `crit` and by carving `pages-*.img`,
then scored with deterministic rules + MITRE ATT&CK tags.

Categories:
  1. network      — live sockets / connections (C2 + DDoS targets)   [inetsk.img, tcp-stream]
  2. injected     — anonymous RWX memory regions (fileless/injected)  [mm-*.img vmas]
  3. deleted_exe  — executables deleted from disk but still running    [files/reg-files.img]
  4. lineage      — process tree (who spawned the malicious process)   [pstree.img + core-*.img]
  5. secrets      — credentials/tokens resident in memory              [pages-*.img carving]

Each finding is a dict:
  {category, label, detail, threat_score(0-100), severity, mitre:[{id,name,tactic}], pid?}

Requires `crit` (ships with CRIU) for 1-4; category 5 works without it.
"""
from __future__ import annotations

import ipaddress
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import List, Dict

# ---- reuse severity mapping from threat_scoring ---------------------------------
try:
    from threat_scoring import severity  # type: ignore
except Exception:
    def severity(s: float) -> str:
        return ("Critical" if s >= 85 else "High" if s >= 60
                else "Medium" if s >= 40 else "Low")

HAVE_CRIT = shutil.which("crit") is not None


def crit_entries(img: Path) -> list:
    """Run `crit show <img>` and return the decoded entries list ([] on any error)."""
    if not HAVE_CRIT or not img.exists():
        return []
    try:
        out = subprocess.run(["crit", "show", str(img)],
                             capture_output=True, timeout=60)
        data = json.loads(out.stdout.decode("utf-8", "ignore") or "{}")
        if isinstance(data, dict):
            return data.get("entries", [])
        return data if isinstance(data, list) else []
    except Exception:
        return []


def crit_text(img: Path) -> str:
    if not HAVE_CRIT or not img.exists():
        return ""
    try:
        return subprocess.run(["crit", "show", str(img)],
                             capture_output=True, timeout=60).stdout.decode("utf-8", "ignore")
    except Exception:
        return ""


def _mk(cat, label, detail, score, mitre, pid=None) -> Dict:
    return {"category": cat, "label": label, "detail": detail,
            "threat_score": float(score), "severity": severity(score),
            "mitre": mitre, "pid": pid}


# ---------------------------------------------------------------- 1. network
def _is_external(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
        return not (ip.is_private or ip.is_loopback or ip.is_unspecified
                    or ip.is_link_local or ip.is_multicast)
    except Exception:
        return False


def _fmt_addr(v) -> str:
    """crit renders addresses as a list of octets/words or a string."""
    if isinstance(v, list):
        try:
            if len(v) == 1:
                return str(ipaddress.ip_address(v[0]))
            return ".".join(str(x) for x in v)
        except Exception:
            return ".".join(str(x) for x in v)
    return str(v)


def network_connections(cpdir: Path) -> List[Dict]:
    findings = []
    for img in list(cpdir.rglob("inetsk.img")) + list(cpdir.rglob("inetsk-*.img")):
        for e in crit_entries(img):
            proto = str(e.get("proto", e.get("type", "")))
            state = str(e.get("state", ""))
            src = _fmt_addr(e.get("src_addr") or e.get("src-addr") or "")
            dst = _fmt_addr(e.get("dst_addr") or e.get("dst-addr") or "")
            sport = e.get("src_port") or e.get("src-port") or ""
            dport = e.get("dst_port") or e.get("dst-port") or ""
            if not dst and not state:
                continue
            external = _is_external(dst)
            listening = "LISTEN" in state.upper()
            label = (f"{proto} {src}:{sport} -> {dst}:{dport} [{state}]"
                     if dst else f"{proto} listen {src}:{sport} [{state}]")
            if external:
                findings.append(_mk(
                    "network", label, "outbound connection to an external host (possible C2)",
                    72, [{"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"},
                         {"id": "T1571", "name": "Non-Standard Port", "tactic": "Command and Control"}]))
            elif not listening and dst:
                findings.append(_mk(
                    "network", label, "active connection recovered from memory",
                    45, [{"id": "T1049", "name": "System Network Connections Discovery", "tactic": "Discovery"}]))
    # many established inbound connections at once == volumetric DDoS fingerprint
    est = [f for f in findings if "ESTABLISH" in f["label"].upper()]
    if len(est) >= 20:
        findings.append(_mk(
            "network", f"{len(est)} concurrent established connections",
            "high concurrent connection count — consistent with a DDoS flood",
            80, [{"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"}]))
    return findings


# ---------------------------------------------------------------- 2. injected / RWX
def injected_code(cpdir: Path) -> List[Dict]:
    findings = []
    for img in cpdir.rglob("mm-*.img"):
        pid = re.search(r"mm-(\d+)", img.name)
        pid = pid.group(1) if pid else "?"
        for e in crit_entries(img):
            for vma in e.get("vmas", []):
                prot = str(vma.get("prot", "")).upper()
                status = str(vma.get("status", "")).upper()
                is_rwx = "PROT_READ" in prot and "PROT_WRITE" in prot and "PROT_EXEC" in prot
                is_anon = "ANON" in status
                if is_rwx and is_anon:
                    start = vma.get("start", 0)
                    end = vma.get("end", 0)
                    try:
                        size = int(end) - int(start)
                    except Exception:
                        size = 0
                    findings.append(_mk(
                        "injected",
                        f"pid {pid}: anonymous RWX region @ {hex(int(start)) if str(start).isdigit() else start} ({size} bytes)",
                        "writable+executable anonymous memory — hallmark of injected / fileless code",
                        90, [{"id": "T1055", "name": "Process Injection", "tactic": "Defense Evasion"},
                             {"id": "T1620", "name": "Reflective Code Loading", "tactic": "Defense Evasion"}],
                        pid=pid))
    return findings


# ---------------------------------------------------------------- 3. deleted-but-running exe
def deleted_executables(cpdir: Path) -> List[Dict]:
    findings, seen = [], set()
    for name in ("reg-files.img", "files.img"):
        for img in cpdir.rglob(name):
            txt = crit_text(img)
            for m in re.findall(r'"name"\s*:\s*"([^"]*\(deleted\)[^"]*)"', txt):
                path = m.replace(" (deleted)", "").strip()
                if path in seen:
                    continue
                seen.add(path)
                findings.append(_mk(
                    "deleted_exe", path,
                    "file was deleted from disk but is still mapped/running in memory "
                    "(anti-forensics; recovered from the memory image)",
                    78, [{"id": "T1070.004", "name": "File Deletion", "tactic": "Defense Evasion"},
                         {"id": "T1620", "name": "Reflective Code Loading", "tactic": "Defense Evasion"}]))
    return findings


# ---------------------------------------------------------------- 4. process lineage
_SUSP_COMM = {"sh", "bash", "dash", "ash", "zsh", "nc", "ncat", "hping3", "wget",
              "curl", "python", "python3", "perl", "xmrig", "busybox", "tftp"}


def process_lineage(cpdir: Path) -> tuple[list, list]:
    """Return (tree_rows, findings). tree_rows = [{pid,ppid,comm}], findings = suspicious spawns."""
    pstree = next(iter(cpdir.rglob("pstree.img")), None)
    if pstree is None:
        return [], []
    comm = {}
    for core in cpdir.rglob("core-*.img"):
        pid = re.search(r"core-(\d+)", core.name)
        if not pid:
            continue
        ents = crit_entries(core)
        if ents:
            tc = ents[0].get("tc", {}) if isinstance(ents[0], dict) else {}
            comm[pid.group(1)] = str(tc.get("comm", "")) if isinstance(tc, dict) else ""
    rows, findings = [], []
    for e in crit_entries(pstree):
        pid = str(e.get("pid", ""))
        ppid = str(e.get("ppid", ""))
        c = comm.get(pid, "")
        rows.append({"pid": pid, "ppid": ppid, "comm": c})
    for r in rows:
        cbase = (r["comm"] or "").split("/")[-1]
        if cbase in _SUSP_COMM:
            parent = next((x["comm"] for x in rows if x["pid"] == r["ppid"]), "")
            findings.append(_mk(
                "lineage", f"{parent or 'init'}(pid {r['ppid']}) -> {cbase}(pid {r['pid']})",
                "a shell/tool process was spawned inside the container",
                50, [{"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"}],
                pid=r["pid"]))
    return rows, findings


# ---------------------------------------------------------------- 5. in-memory secrets
_SECRET_PATTERNS = [
    ("AWS access key", re.compile(rb"AKIA[0-9A-Z]{16}")),
    ("private key", re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("JWT", re.compile(rb"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("GitHub token", re.compile(rb"ghp_[A-Za-z0-9]{36}")),
    ("Slack token", re.compile(rb"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("Bearer token", re.compile(rb"(?i)bearer\s+[A-Za-z0-9._\-]{16,}")),
    ("credential assignment",
     re.compile(rb"(?i)(?:password|passwd|secret|api[_-]?key|access[_-]?key|db[_-]?pass|token)"
                rb"\s*[=:]\s*['\"]?([A-Za-z0-9/+_\-.@!]{6,})")),
]


def _redact(s: str) -> str:
    return s[:6] + "…" + f"[{len(s)} chars]" if len(s) > 8 else "…"


def in_memory_secrets(cpdir: Path, limit: int = 40) -> List[Dict]:
    findings, seen = [], set()
    for pages in sorted(cpdir.rglob("pages-*.img")):
        try:
            data = pages.read_bytes()
        except Exception:
            continue
        for label, rx in _SECRET_PATTERNS:
            for m in rx.findall(data):
                raw = (m if isinstance(m, bytes) else m[0]) if not isinstance(m, tuple) else m[0]
                token = raw.decode("utf-8", "ignore")
                key = (label, token[:24])
                if key in seen or len(token) < 6:
                    continue
                seen.add(key)
                findings.append(_mk(
                    "secret", f"{label}: {_redact(token)}",
                    "credential/secret material found resident in process memory",
                    66, [{"id": "T1552", "name": "Unsecured Credentials", "tactic": "Credential Access"}]))
                if len(findings) >= limit:
                    return findings
    return findings


# ---------------------------------------------------------------- orchestrator
def collect_artifacts(cpdir: Path, rootfs: Path | None = None) -> Dict:
    """Return {'network':[...], 'injected':[...], 'deleted_exe':[...],
               'lineage_rows':[...], 'lineage':[...], 'secrets':[...],
               'all':[...flattened scored findings...], 'have_crit': bool}."""
    net = network_connections(cpdir)
    inj = injected_code(cpdir)
    deleted = deleted_executables(cpdir)
    rows, lineage = process_lineage(cpdir)
    secrets = in_memory_secrets(cpdir)
    flat = net + inj + deleted + lineage + secrets
    return {"network": net, "injected": inj, "deleted_exe": deleted,
            "lineage_rows": rows, "lineage": lineage, "secrets": secrets,
            "all": flat, "have_crit": HAVE_CRIT}


if __name__ == "__main__":
    import sys
    res = collect_artifacts(Path(sys.argv[1]))
    print("have_crit:", res["have_crit"])
    for f in res["all"]:
        print(f"  [{f['severity']:8s}] {f['category']:10s} {f['label']}")
