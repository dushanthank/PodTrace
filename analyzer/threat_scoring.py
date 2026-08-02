"""
Unified threat prioritization for ConPoint.

Turns raw model outputs (file P(malicious), command priority) into a single,
explainable, ranked list of threats with:
  * a 0-100 THREAT SCORE that fuses the ML confidence with forensic context
    (where the file lives, whether a command was resident in RAM, etc.)
  * a SEVERITY tier  (Critical / High / Medium / Low)
  * MITRE ATT&CK technique tags  (so the report speaks the SOC/analyst language)

This is the "prioritize" half of the project: the panel sees not just "malicious
y/n" but a defensible ordering of what matters most and why.
"""
from __future__ import annotations

import re
from typing import Dict, List

# --------------------------------------------------------------------------- MITRE
# (pattern -> (technique id, name, tactic))  for reconstructed commands
_MITRE_CMD = [
    (r"\b(wget|curl|tftp)\b", ("T1105", "Ingress Tool Transfer", "Command and Control")),
    (r"\|\s*(sh|bash)\b|bash\s+-c|sh\s+-c", ("T1059", "Command and Scripting Interpreter", "Execution")),
    (r"chmod\s+\+x", ("T1222", "File and Directory Permissions Modification", "Defense Evasion")),
    (r"\b(nc|ncat)\b.*-e|/dev/tcp/|bash\s+-i", ("T1059.004", "Unix Shell (reverse shell)", "Execution")),
    (r"base64\s+-d|openssl\s+enc", ("T1140", "Deobfuscate/Decode Files or Information", "Defense Evasion")),
    (r"\b(hping3|mausezahn|t50|slowloris|goldeneye|hulk)\b|--flood|synflood|udpflood",
     ("T1498", "Network Denial of Service", "Impact")),
    (r":\(\)\s*\{\s*:\|:&|for\s*\(\(", ("T1499", "Endpoint Denial of Service", "Impact")),
    (r"\b(xmrig|minerd|stratum\+tcp)\b", ("T1496", "Resource Hijacking", "Impact")),
    (r"crontab|/etc/rc\.local|/etc/cron|systemctl\s+enable",
     ("T1053", "Scheduled Task/Job", "Persistence")),
    (r"\b(iptables|ufw)\b.*(-F|disable|stop)|setenforce\s+0",
     ("T1562", "Impair Defenses", "Defense Evasion")),
    (r"kill(all)?\b.*-9|pkill", ("T1489", "Service Stop", "Impact")),
    (r"history\s+-c|>\s*~/\.bash_history|unset\s+HISTFILE",
     ("T1070.003", "Clear Command History", "Defense Evasion")),
]
_MITRE_CMD = [(re.compile(p, re.IGNORECASE), t) for p, t in _MITRE_CMD]


def mitre_for_command(cmd: str) -> List[Dict[str, str]]:
    hits, seen = [], set()
    for rx, (tid, name, tactic) in _MITRE_CMD:
        if rx.search(cmd) and tid not in seen:
            seen.add(tid)
            hits.append({"id": tid, "name": name, "tactic": tactic})
    return hits


def mitre_for_file(feats: Dict[str, float]) -> List[Dict[str, str]]:
    hits = [{"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control"}]
    if feats.get("has_upx", 0) or feats.get("entropy", 0) >= 7.2:
        hits.append({"id": "T1027", "name": "Obfuscated/Packed Files", "tactic": "Defense Evasion"})
    if feats.get("n_ddos_tokens", 0) >= 1 or feats.get("imp_socket", 0):
        hits.append({"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"})
    if feats.get("imp_ptrace", 0):
        hits.append({"id": "T1622", "name": "Debugger Evasion", "tactic": "Defense Evasion"})
    return hits


# --------------------------------------------------------------------------- severity
def severity(score_0_100: float) -> str:
    if score_0_100 >= 85:
        return "Critical"
    if score_0_100 >= 60:
        return "High"
    if score_0_100 >= 40:
        return "Medium"
    return "Low"


SEVERITY_RANK = {"Critical": 3, "High": 2, "Medium": 1, "Low": 0}


# --------------------------------------------------------------------------- context
def _file_context_multiplier(path: str) -> tuple[float, list[str]]:
    """Forensic context: WHERE a file lives changes how threatening it is."""
    mult, notes = 1.0, []
    p = path.lower()
    if re.search(r"^/(tmp|dev/shm|var/tmp)/", p):
        mult *= 1.25; notes.append("dropped in world-writable temp dir")
    if re.search(r"/\.[^/]+$", p):
        mult *= 1.10; notes.append("hidden filename (dot-prefixed)")
    if re.search(r"/(bin|sbin|usr/bin|usr/sbin)/", p):
        mult *= 1.10; notes.append("planted in a system binary path")
    return mult, notes


def _command_context_multiplier(source: str) -> tuple[float, list[str]]:
    mult, notes = 1.0, []
    if source == "ram-pages":
        mult *= 1.20; notes.append("recovered live from RAM (was resident in memory)")
    elif source == "process-cmdline":
        mult *= 1.15; notes.append("captured from the running process table")
    return mult, notes


# --------------------------------------------------------------------------- fuse
def score_file_threat(scored_file: dict, feats: Dict[str, float]) -> dict:
    base = scored_file["p_malicious"] * 100.0
    mult, notes = _file_context_multiplier(scored_file["path"])
    threat = min(100.0, base * mult)
    sev = severity(threat)
    return {**scored_file,
            "type": "file",
            "threat_score": round(threat, 1),
            "severity": sev,
            "context_notes": notes,
            "mitre": mitre_for_file(feats)}


def score_command_threat(scored_cmd: dict) -> dict:
    base = scored_cmd["priority"] * 100.0
    mult, notes = _command_context_multiplier(scored_cmd.get("source", ""))
    threat = min(100.0, base * mult)
    sev = severity(threat)
    return {**scored_cmd,
            "type": "command",
            "threat_score": round(threat, 1),
            "severity": sev,
            "context_notes": notes,
            "mitre": mitre_for_command(scored_cmd["command"])}


def unified_ranking(file_threats: List[dict], cmd_threats: List[dict]) -> List[dict]:
    """One ranked list across files AND commands, worst first."""
    items = []
    for f in file_threats:
        items.append({"kind": "file", "label": f["path"],
                      "threat_score": f["threat_score"], "severity": f["severity"],
                      "mitre": [m["id"] for m in f["mitre"]]})
    for c in cmd_threats:
        items.append({"kind": "command", "label": c["command"][:70],
                      "threat_score": c["threat_score"], "severity": c["severity"],
                      "mitre": [m["id"] for m in c["mitre"]]})
    items.sort(key=lambda x: (SEVERITY_RANK[x["severity"]], x["threat_score"]),
               reverse=True)
    return items


def incident_risk(items: List[dict]) -> dict:
    """A single top-line number for the incident (max + volume-weighted)."""
    if not items:
        return {"score": 0.0, "severity": "Low", "n_critical": 0, "n_high": 0}
    top = max(i["threat_score"] for i in items)
    ncrit = sum(i["severity"] == "Critical" for i in items)
    nhigh = sum(i["severity"] == "High" for i in items)
    # top signal dominates; extra critical/high artifacts nudge it up
    score = min(100.0, top + 3 * ncrit + 1.5 * nhigh)
    return {"score": round(score, 1), "severity": severity(score),
            "n_critical": ncrit, "n_high": nhigh}
