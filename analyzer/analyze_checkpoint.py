#!/usr/bin/env python3
"""
End-to-end checkpoint analyzer  (the "analyzer tool" you run in the demo).

Input : a kubelet/CRIU checkpoint .tar (or an already-extracted directory)
Output: a ranked threat report  ->  report.json  +  report.html

Pipeline
    1. extract the checkpoint archive
    2. unpack rootfs-diff.tar  -> recover files the container created/changed
    3. reconstruct executed commands  (bash_history + strings from RAM pages,
       and process cmdlines via `crit` if available)
    4. score every recovered ELF with the trained file classifier   -> P(malicious)
    5. score every command with the rule/IOC layer + command model   -> priority
    6. emit report.json and a self-contained report.html, worst-first

Usage
    python3 analyze_checkpoint.py --checkpoint /path/checkpoint.tar \
        --models models --out reports/incident-001
"""
import argparse
import html
import json
import re
import shutil
import subprocess
import sys
import tarfile
from datetime import datetime, timezone
from pathlib import Path

import joblib

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from features.elf_features import extract_features, is_elf, sha256_of  # noqa: E402
from features.command_features import rule_score  # noqa: E402
from explain import make_explainer, local_explanation  # noqa: E402
import threat_scoring as ts  # noqa: E402
import artifacts as art  # noqa: E402

# command-like strings we hunt for in RAM pages
# NOTE: sh\b and nc\b use word boundaries so they don't match SHA*/SHAKE*/nC* noise
# from OpenSSL .rodata sections embedded in statically-linked binaries (e.g. nginx).
_CMD_RE = re.compile(
    rb"(?:^|\x00)((?:sudo\s+)?(?:wget|curl|tftp|bash|sh\b|nc\b|ncat|python[0-9.]*|"
    rb"chmod|hping3|nmap|base64|/tmp/[\w./-]+|/dev/shm/[\w./-]+)[^\x00\n]{0,200})",
    re.IGNORECASE,
)

# OpenSSL / libcrypto hash-algorithm name strings that appear in nginx's read-only data
# section.  The RAM carver matches them because they start with 'sh' or 'nc' (case-
# insensitive).  These are NOT commands and must never reach the ML scorer.
#
# Pattern covers all SHA/SHAKE/MD/AES variants:
#   SHA256, SHA-256, SHA2-256, SHA3-256, SHA512-224, SHA-512/256, SHAKE128, etc.
_BENIGN_CMD_RE = re.compile(
    r"^(?:"
    r"SHA[23]?[-_]?\d+(?:[-/]\d+)?"   # SHA256, SHA-256, SHA2-512, SHA512-224, SHA-512/256
    r"|SHAKE-?\d+"                      # SHAKE128, SHAKE-256
    r"|MD[245]"                         # MD2, MD4, MD5
    r"|AES-\d+(?:-\w+)?"               # AES-128-CBC etc.
    r"|shtml"                           # nginx SSI extension token
    r")$",
    re.IGNORECASE,
)


# ----------------------------------------------------------------------------- extract
def extract_checkpoint(src: Path, workdir: Path) -> Path:
    workdir.mkdir(parents=True, exist_ok=True)
    if src.is_dir():
        return src
    print(f"[1] extracting checkpoint archive: {src.name}")
    with tarfile.open(src) as tf:
        tf.extractall(workdir, filter="data")
    return workdir


def unpack_rootfs(cpdir: Path, workdir: Path) -> Path:
    rootfs = workdir / "rootfs"
    diff = cpdir / "rootfs-diff.tar"
    if diff.exists():
        rootfs.mkdir(exist_ok=True)
        print("[2] unpacking rootfs-diff.tar (recovered files)")
        with tarfile.open(diff) as tf:
            tf.extractall(rootfs, filter="data")
    else:
        print("[2] no rootfs-diff.tar found; scanning extracted tree directly")
        rootfs = cpdir
    return rootfs


# ----------------------------------------------------------------------------- files
def collect_files(rootfs: Path) -> list[dict]:
    out = []
    for fp in rootfs.rglob("*"):
        if not fp.is_file() or fp.is_symlink():
            continue
        try:
            size = fp.stat().st_size
        except OSError:
            continue
        out.append({"path": "/" + str(fp.relative_to(rootfs)),
                    "abspath": str(fp), "size": size, "is_elf": is_elf(fp)})
    return out


# ----------------------------------------------------------------------------- commands
def commands_from_history(rootfs: Path) -> list[dict]:
    found = []
    for hist in rootfs.rglob("*.bash_history"):
        try:
            for line in hist.read_text(errors="ignore").splitlines():
                line = line.strip()
                if line:
                    found.append({"command": line,
                                  "source": f"history:{hist.name}"})
        except Exception:
            pass
    # also common shell histories without dot-glob match
    for name in (".bash_history", ".sh_history", ".ash_history", ".zsh_history"):
        for hist in rootfs.rglob(name):
            try:
                for line in hist.read_text(errors="ignore").splitlines():
                    line = line.strip()
                    if line:
                        found.append({"command": line, "source": "history"})
            except Exception:
                pass
    return found


def commands_from_pages(cpdir: Path, limit: int = 200) -> list[dict]:
    found, seen = [], set()
    for pages in sorted(cpdir.rglob("pages-*.img")):
        try:
            data = pages.read_bytes()
        except Exception:
            continue
        for m in _CMD_RE.findall(data):
            cmd = m.decode("utf-8", "ignore").strip()
            if (3 < len(cmd) < 250
                    and cmd not in seen
                    and cmd.isascii()                   # drop corrupted non-ASCII garbage
                    and not _BENIGN_CMD_RE.match(cmd)):  # drop OpenSSL symbol-table noise
                seen.add(cmd)
                found.append({"command": cmd, "source": "ram-pages"})
                if len(found) >= limit:
                    return found
    return found


def commands_from_crit(cpdir: Path) -> list[dict]:
    """Optional: use CRIU's `crit` to read process cmdlines. Skipped if crit absent."""
    if shutil.which("crit") is None:
        return []
    found = []
    for img in sorted(cpdir.rglob("mm-*.img")) + sorted(cpdir.rglob("core-*.img")):
        try:
            out = subprocess.run(["crit", "show", str(img)],
                                 capture_output=True, timeout=20)
            txt = out.stdout.decode("utf-8", "ignore")
            for mm in re.findall(r'"cmdline"\s*:\s*"([^"]+)"', txt):
                found.append({"command": mm.replace("\\u0000", " ").strip(),
                              "source": "process-cmdline"})
        except Exception:
            pass
    return found


def dedup_commands(cmds: list[dict]) -> list[dict]:
    seen, out = set(), []
    for c in cmds:
        key = c["command"]
        if key and key not in seen:
            seen.add(key)
            out.append(c)
    return out


# ----------------------------------------------------------------------------- scoring
def load_models(models_dir: Path):
    file_bundle = cmd_bundle = None
    fp = models_dir / "file_clf.joblib"
    cp = models_dir / "command_clf.joblib"
    if fp.exists():
        file_bundle = joblib.load(fp)
    else:
        print(f"[!] {fp} missing — train the file model first (train_file_clf.py)")
    if cp.exists():
        cmd_bundle = joblib.load(cp)
    return file_bundle, cmd_bundle


def score_files(files: list[dict], bundle) -> list[dict]:
    results = []
    if not bundle:
        return results
    order = bundle["features"]
    explainer = make_explainer(bundle["model"])
    for f in files:
        if not f["is_elf"]:
            continue
        feats = extract_features(f["abspath"], include_histogram=True)
        x_row = [feats.get(c, 0.0) for c in order]
        p = float(bundle["model"].predict_proba([x_row])[0][1])
        entry = {
            "path": f["path"], "sha256": sha256_of(f["abspath"]),
            "size": f["size"], "p_malicious": round(p, 4),
            "verdict": "malicious" if p >= bundle["threshold"] else "benign",
            # SHAP: which features pushed THIS file's verdict, and which way
            "explanation": local_explanation(explainer, x_row, order, k=6),
        }
        # fuse ML confidence + forensic context -> threat score / severity / MITRE
        results.append(ts.score_file_threat(entry, feats))
    results.sort(key=lambda r: r["threat_score"], reverse=True)
    return results


def score_commands(cmds: list[dict], bundle) -> list[dict]:
    results = []
    for c in cmds:
        # Defense-in-depth: skip anything that slipped through the carver filter
        if not c["command"].isascii() or _BENIGN_CMD_RE.match(c["command"]):
            continue
        rscore, reasons = rule_score(c["command"])
        mscore = 0.0
        if bundle:
            try:
                mscore = float(bundle["pipeline"].predict_proba([c["command"]])[0][1])
            except Exception:
                pass
        final = max(rscore, mscore)
        entry = {
            "command": c["command"], "source": c["source"],
            "rule_score": round(rscore, 3), "model_score": round(mscore, 3),
            "priority": round(final, 3),
            "verdict": "suspicious" if final >= 0.5 else "benign",
            "reasons": reasons,
        }
        results.append(ts.score_command_threat(entry))
    results.sort(key=lambda r: r["threat_score"], reverse=True)
    return results


# ----------------------------------------------------------------------------- report
_SEV_COLOR = {"Critical": "#c0341d", "High": "#e8730c", "Medium": "#c9a400", "Low": "#5a9"}


def render_html(report: dict) -> str:
    def esc(x): return html.escape(str(x))

    def badge(sev):
        return (f"<span class='sev' style='background:{_SEV_COLOR.get(sev,'#999')}'>"
                f"{esc(sev)}</span>")

    def mitre_tags(mitre):
        return " ".join(f"<span class='att'>{esc(m['id'])}</span>" for m in mitre)

    def shap_block(expl):
        if not expl:
            return ""
        items = "".join(
            f"<li><code>{esc(e['feature'])}</code> = {esc(e['value'])} "
            f"<span class='{'push' if e['shap']>0 else 'pull'}'>"
            f"SHAP {e['shap']:+.2f} {esc(e['direction'])}</span></li>"
            for e in expl)
        return f"<details class='xai'><summary>why?</summary><ul>{items}</ul></details>"

    def art_rows(findings):
        out = ""
        for f in findings:
            out += (f"<tr class='r-{f['severity'].lower()}'>"
                    f"<td>{f['threat_score']:.0f} {badge(f['severity'])}</td>"
                    f"<td><code>{esc(f['label'])}</code></td>"
                    f"<td>{mitre_tags(f['mitre'])}</td>"
                    f"<td class='ft'>{esc(f['detail'])}</td></tr>")
        return out

    def lineage_rows(rows, sus_pids):
        out = ""
        for r in rows:
            cls = "bad" if r["pid"] in sus_pids else "ok"
            out += (f"<tr class='r-{'high' if r['pid'] in sus_pids else 'low'}'>"
                    f"<td>{esc(r['pid'])}</td><td>{esc(r['ppid'])}</td>"
                    f"<td><code>{esc(r['comm'])}</code></td></tr>")
        return out

    mal_files = [f for f in report["files"] if f["verdict"] == "malicious"]
    sus_cmds = [c for c in report["commands"] if c["verdict"] == "suspicious"]
    arts = report.get("artifacts", {})
    inc = report["meta"]["incident_risk"]

    def prio_rows(rows):
        out = ""
        for r in rows:
            out += (f"<tr class='r-{r['severity'].lower()}'><td>{r['threat_score']:.0f}</td>"
                    f"<td>{badge(r['severity'])}</td><td>{esc(r['kind'])}</td>"
                    f"<td><code>{esc(r['label'])}</code></td>"
                    f"<td>{' '.join('<span class=att>'+esc(m)+'</span>' for m in r['mitre'])}</td></tr>")
        return out

    def file_rows(rows):
        out = ""
        for f in rows:
            notes = "; ".join(f.get("context_notes", []))
            out += (f"<tr class='r-{f['severity'].lower()}'>"
                    f"<td>{f['threat_score']:.0f} {badge(f['severity'])}</td>"
                    f"<td><code>{esc(f['path'])}</code>{shap_block(f.get('explanation'))}</td>"
                    f"<td>{f['p_malicious']:.3f}</td>"
                    f"<td>{mitre_tags(f['mitre'])}</td>"
                    f"<td class='sha'>{esc(f['sha256'][:16])}…</td>"
                    f"<td class='ft'>{esc(notes)}</td></tr>")
        return out

    def cmd_rows(rows):
        out = ""
        for c in rows:
            notes = "; ".join(c["reasons"] + c.get("context_notes", []))
            out += (f"<tr class='r-{c['severity'].lower()}'>"
                    f"<td>{c['threat_score']:.0f} {badge(c['severity'])}</td>"
                    f"<td><code>{esc(c['command'])}</code></td>"
                    f"<td>{esc(c['source'])}</td>"
                    f"<td>{mitre_tags(c['mitre'])}</td>"
                    f"<td class='ft'>{esc(notes)}</td></tr>")
        return out

    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>ConPoint Threat Report — {esc(report['meta']['checkpoint'])}</title>
<style>
 body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:2rem;color:#1a1a1a;background:#fafafa}}
 h1{{margin-bottom:0}} .sub{{color:#666;margin-top:.25rem}}
 .banner{{margin:1.2rem 0;padding:1rem 1.25rem;border-radius:10px;color:#fff;
   background:{_SEV_COLOR.get(inc['severity'],'#999')}}}
 .banner .big{{font-size:2.4rem;font-weight:800;line-height:1}}
 .cards{{display:flex;gap:1rem;margin:1rem 0}}
 .card{{background:#fff;border:1px solid #e3e3e3;border-radius:10px;padding:.8rem 1.1rem;flex:1}}
 .card .n{{font-size:1.8rem;font-weight:700}} .card.red .n{{color:#c0341d}}
 table{{border-collapse:collapse;width:100%;background:#fff;margin:.5rem 0 2rem}}
 th,td{{border:1px solid #e3e3e3;padding:.5rem .6rem;text-align:left;font-size:.88rem;vertical-align:top}}
 th{{background:#f0f0f0}}
 tr.r-critical{{background:#fdecea}} tr.r-high{{background:#fef3e7}}
 tr.r-medium{{background:#fdf9e3}} tr.r-low{{background:#fff}}
 code{{background:#f4f4f4;padding:.1rem .3rem;border-radius:4px;font-size:.82rem}}
 .sha{{color:#888;font-family:monospace}} .ft{{color:#555;font-size:.8rem}}
 .sev{{color:#fff;padding:.05rem .45rem;border-radius:20px;font-size:.72rem;font-weight:700}}
 .att{{background:#2d3a55;color:#fff;padding:.05rem .35rem;border-radius:4px;
   font-size:.72rem;font-family:monospace;margin-right:.15rem}}
 .xai{{margin-top:.35rem}} .xai summary{{cursor:pointer;color:#2d3a55;font-size:.8rem}}
 .xai ul{{margin:.3rem 0 .2rem 1rem;padding:0;font-size:.78rem}}
 .push{{color:#c0341d;font-weight:600}} .pull{{color:#2e7d32}}
 h2{{border-bottom:2px solid #ddd;padding-bottom:.3rem;margin-top:2rem}}
</style></head><body>
<h1>ConPoint — Pod Memory Forensic Report</h1>
<div class="sub">Checkpoint: <b>{esc(report['meta']['checkpoint'])}</b> ·
 Pod: <b>{esc(report['meta'].get('pod','n/a'))}</b> ·
 Generated: {esc(report['meta']['generated'])}</div>

<div class="banner">
 <div class="big">{inc['score']:.0f}/100 · {esc(inc['severity'])}</div>
 Incident threat level — {inc['n_critical']} critical, {inc['n_high']} high-severity artifacts
</div>

<div class="cards">
 <div class="card red"><div class="n">{len(mal_files)}</div>malicious files</div>
 <div class="card red"><div class="n">{len(sus_cmds)}</div>suspicious commands</div>
 <div class="card"><div class="n">{report['meta']['n_files']}</div>files recovered</div>
 <div class="card"><div class="n">{report['meta']['n_commands']}</div>commands recovered</div>
</div>
<div class="cards">
 <div class="card red"><div class="n">{report['meta'].get('n_network',0)}</div>network connections</div>
 <div class="card red"><div class="n">{report['meta'].get('n_injected',0)}</div>injected/RWX regions</div>
 <div class="card red"><div class="n">{report['meta'].get('n_deleted_exe',0)}</div>deleted-but-running</div>
 <div class="card red"><div class="n">{report['meta'].get('n_secrets',0)}</div>in-memory secrets</div>
</div>

<h2>Prioritized threats (files + commands, worst-first)</h2>
<table><tr><th>Threat</th><th>Severity</th><th>Type</th><th>Artifact</th><th>MITRE</th></tr>
 {prio_rows(report['ranking'][:15]) or "<tr><td colspan=5>none</td></tr>"}</table>

<h2>Malicious files — with SHAP explanation</h2>
<table><tr><th>Threat</th><th>Path (why?)</th><th>P(mal)</th><th>MITRE</th>
 <th>SHA-256</th><th>Context</th></tr>
 {file_rows(mal_files) or "<tr><td colspan=6>none flagged</td></tr>"}</table>
<details><summary>All {report['meta']['n_files']} recovered files</summary>
<table><tr><th>Threat</th><th>Path (why?)</th><th>P(mal)</th><th>MITRE</th>
 <th>SHA-256</th><th>Context</th></tr>{file_rows(report['files'])}</table></details>

<h2>Suspicious commands — classified &amp; ATT&amp;CK-tagged</h2>
<table><tr><th>Threat</th><th>Command</th><th>Source</th><th>MITRE</th><th>Why flagged</th></tr>
 {cmd_rows(sus_cmds) or "<tr><td colspan=5>none flagged</td></tr>"}</table>
<details><summary>All {report['meta']['n_commands']} recovered commands</summary>
<table><tr><th>Threat</th><th>Command</th><th>Source</th><th>MITRE</th><th>Why flagged</th></tr>
 {cmd_rows(report['commands'])}</table></details>

<h2>Memory-only artifacts <span style="font-size:.7em;color:#666">
 (recovered from RAM — would be lost on crash)</span></h2>

<h3>Network connections (C2 &amp; DDoS evidence)</h3>
<table><tr><th>Threat</th><th>Connection</th><th>MITRE</th><th>Detail</th></tr>
 {art_rows(arts.get('network', [])) or "<tr><td colspan=4>none recovered</td></tr>"}</table>

<h3>Injected / fileless code (anonymous RWX memory)</h3>
<table><tr><th>Threat</th><th>Region</th><th>MITRE</th><th>Detail</th></tr>
 {art_rows(arts.get('injected', [])) or "<tr><td colspan=4>none detected</td></tr>"}</table>

<h3>Deleted-but-running executables (anti-forensics)</h3>
<table><tr><th>Threat</th><th>Path</th><th>MITRE</th><th>Detail</th></tr>
 {art_rows(arts.get('deleted_exe', [])) or "<tr><td colspan=4>none detected</td></tr>"}</table>

<h3>In-memory secrets (credentials resident in RAM)</h3>
<table><tr><th>Threat</th><th>Secret</th><th>MITRE</th><th>Detail</th></tr>
 {art_rows(arts.get('secrets', [])) or "<tr><td colspan=4>none found</td></tr>"}</table>

<h3>Process lineage (suspicious spawns highlighted)</h3>
<table><tr><th>Threat</th><th>Parent → child</th><th>MITRE</th><th>Detail</th></tr>
 {art_rows(arts.get('lineage', [])) or "<tr><td colspan=4>no suspicious spawns</td></tr>"}</table>
<details><summary>Full process tree ({len(arts.get('lineage_rows', []))} processes)</summary>
<table><tr><th>PID</th><th>PPID</th><th>comm</th></tr>
 {lineage_rows(arts.get('lineage_rows', []), {f['pid'] for f in arts.get('lineage', [])})}</table></details>
</body></html>"""


# ----------------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--checkpoint", required=True, help="checkpoint .tar or extracted dir")
    ap.add_argument("--models", default="models")
    ap.add_argument("--out", default="reports/incident")
    ap.add_argument("--pod", default="")
    ap.add_argument("--workdir", default="")
    args = ap.parse_args()

    src = Path(args.checkpoint)
    out = Path(args.out); out.mkdir(parents=True, exist_ok=True)
    workdir = Path(args.workdir) if args.workdir else out / "work"

    cpdir = extract_checkpoint(src, workdir)
    rootfs = unpack_rootfs(cpdir, workdir)

    files = collect_files(rootfs)
    print(f"    recovered {len(files)} files "
          f"({sum(f['is_elf'] for f in files)} ELF)")

    print("[3] reconstructing executed commands")
    cmds = dedup_commands(commands_from_history(rootfs)
                          + commands_from_crit(cpdir)
                          + commands_from_pages(cpdir))
    print(f"    recovered {len(cmds)} unique commands")

    file_bundle, cmd_bundle = load_models(Path(args.models))
    print("[4] classifying files (ML + SHAP explanation)")
    scored_files = score_files(files, file_bundle)
    # Append non-ELF files as benign Low entries so the "all files" dropdown is complete
    from features.elf_features import sha256_of as _sha256
    for f in files:
        if not f["is_elf"]:
            scored_files.append({
                "path": f["path"], "sha256": _sha256(f["abspath"]),
                "size": f["size"], "p_malicious": 0.0, "verdict": "benign",
                "explanation": [], "type": "file", "threat_score": 0.0,
                "severity": "Low", "context_notes": ["not an ELF binary — not scored"],
                "mitre": [],
            })
    print("[5] classifying commands (rules + ML) + MITRE ATT&CK tagging")
    scored_cmds = score_commands(cmds, cmd_bundle)

    print("[6] recovering memory-only artifacts (network / injected / deleted-exe / lineage / secrets)")
    arts = art.collect_artifacts(cpdir, rootfs)
    if not arts["have_crit"]:
        print("    [!] `crit` not found — network/injected/deleted-exe/lineage need CRIU's crit;"
              " secrets still carved from RAM")
    print(f"    network={len(arts['network'])}  injected={len(arts['injected'])}  "
          f"deleted-exe={len(arts['deleted_exe'])}  suspicious-procs={len(arts['lineage'])}  "
          f"secrets={len(arts['secrets'])}")

    print("[7] prioritizing threats (context fusion + severity)")
    ranking = ts.unified_ranking(scored_files, scored_cmds)
    for f in arts["all"]:            # fold memory artifacts into the unified ranking
        ranking.append({"kind": f["category"], "label": f["label"],
                        "threat_score": f["threat_score"], "severity": f["severity"],
                        "mitre": [m["id"] for m in f["mitre"]]})
    ranking.sort(key=lambda x: (ts.SEVERITY_RANK[x["severity"]], x["threat_score"]), reverse=True)
    inc = ts.incident_risk(ranking)

    report = {
        "meta": {
            "checkpoint": src.name,
            "pod": args.pod,
            "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "n_files": len(files), "n_commands": len(cmds),
            "n_malicious_files": sum(f["verdict"] == "malicious" for f in scored_files),
            "n_suspicious_commands": sum(c["verdict"] == "suspicious" for c in scored_cmds),
            "n_network": len(arts["network"]), "n_injected": len(arts["injected"]),
            "n_deleted_exe": len(arts["deleted_exe"]), "n_secrets": len(arts["secrets"]),
            "incident_risk": inc,
        },
        "ranking": ranking,
        "files": scored_files,
        "commands": scored_cmds,
        "artifacts": arts,
    }
    (out / "report.json").write_text(json.dumps(report, indent=2))
    (out / "report.html").write_text(render_html(report))

    m = report["meta"]
    print(f"\n[8] REPORT READY -> {out/'report.html'}")
    print(f"    incident threat level: {inc['score']:.0f}/100 ({inc['severity']})")
    print(f"    malicious files:       {m['n_malicious_files']}")
    print(f"    suspicious commands:   {m['n_suspicious_commands']}")
    print(f"    network / injected / deleted-exe / secrets: "
          f"{m['n_network']} / {m['n_injected']} / {m['n_deleted_exe']} / {m['n_secrets']}")


if __name__ == "__main__":
    main()
