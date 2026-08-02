#!/usr/bin/env python3
"""
PodTrace auto-trigger watcher  (Phase 1 of the pipeline).

Polls a pod's health signals; when the crash-risk score crosses a threshold it:
    1. checkpoints the pod via the kubelet checkpoint API (container keeps running)
    2. moves the checkpoint .tar to the storage/offload directory
    3. deletes the pod

Because the checkpoint is a point-in-time copy, killing afterwards loses nothing.

Signals (all via `kubectl`, no extra libs):
    * memory usage / memory limit          (metrics-server: `kubectl top`)
    * container restartCount                (pod status)
    * lastState OOMKilled                   (pod status)
    * not Ready / waiting reason            (pod status)

Requires: kubectl, metrics-server, and the kubelet client certs used for checkpoint.
Run it on the node (or wherever kubectl + the certs are), pointed at your pod.

Example:
    sudo python3 watcher.py \
        --namespace default --pod webserver --container webserver \
        --threshold 0.80 --interval 5 \
        --storage /mnt/hgfs/cpz/vmcpz/k8s \
        --kubelet-host localhost --kubelet-port 10250 \
        --key /etc/kubernetes/pki/apiserver-kubelet-client.key \
        --cert /etc/kubernetes/pki/apiserver-kubelet-client.crt \
        --cacert /etc/kubernetes/pki/ca.crt
"""
import argparse
import json
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

MEM_UNITS = {"Ki": 1024, "Mi": 1024**2, "Gi": 1024**3,
             "K": 1000, "M": 1000**2, "G": 1000**3, "": 1}


def sh(cmd: list[str]) -> str:
    return subprocess.run(cmd, capture_output=True, text=True).stdout


def parse_mem(v: str) -> float:
    m = re.match(r"(\d+)([A-Za-z]*)", v.strip())
    if not m:
        return 0.0
    return float(m.group(1)) * MEM_UNITS.get(m.group(2), 1)


def pod_json(ns: str, pod: str) -> dict:
    out = sh(["kubectl", "get", "pod", pod, "-n", ns, "-o", "json"])
    return json.loads(out) if out else {}


def mem_usage_bytes(ns: str, pod: str) -> float:
    # `kubectl top pod <pod> --no-headers` -> "NAME  CPU(cores)  MEMORY(bytes)"
    out = sh(["kubectl", "top", "pod", pod, "-n", ns, "--no-headers"])
    parts = out.split()
    return parse_mem(parts[2]) if len(parts) >= 3 else 0.0


def compute_risk(ns: str, pod: str, container: str) -> tuple[float, dict]:
    pj = pod_json(ns, pod)
    if not pj:
        return 0.0, {"error": "pod not found"}
    limit = 0.0
    for c in pj.get("spec", {}).get("containers", []):
        if c["name"] == container:
            lim = c.get("resources", {}).get("limits", {}).get("memory")
            if lim:
                limit = parse_mem(lim)
    usage = mem_usage_bytes(ns, pod)
    mem_ratio = (usage / limit) if limit else 0.0

    restarts = 0
    oom = 0
    not_ready = 0
    for cs in pj.get("status", {}).get("containerStatuses", []):
        if cs["name"] == container:
            restarts = cs.get("restartCount", 0)
            last = cs.get("lastState", {}).get("terminated", {})
            if last.get("reason") == "OOMKilled":
                oom = 1
            if not cs.get("ready", True):
                not_ready = 1

    # memory can trip the trigger on its own (mem_ratio ~0.85 -> ~0.77, +not_ready -> >0.9)
    risk = min(1.0,
               0.90 * min(mem_ratio, 1.0)
               + 0.20 * min(restarts / 3.0, 1.0)
               + 0.25 * oom
               + 0.15 * not_ready)
    signals = {"mem_ratio": round(mem_ratio, 3), "restarts": restarts,
               "oom": oom, "not_ready": not_ready, "usage_mb": round(usage / 1e6, 1),
               "limit_mb": round(limit / 1e6, 1)}
    return round(risk, 3), signals


def checkpoint(args) -> bool:
    url = (f"https://{args.kubelet_host}:{args.kubelet_port}"
           f"/checkpoint/{args.namespace}/{args.pod}/{args.container}")
    cmd = ["curl", "-sk", "-X", "POST", url,
           "--key", args.key, "--cert", args.cert, "--cacert", args.cacert]
    print(f"    [checkpoint] POST {url}")
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(f"    [!] checkpoint failed: {r.stderr[:200]}")
        return False
    print(f"    [checkpoint] kubelet response: {r.stdout[:200]}")
    return True


def offload(args) -> Path | None:
    src_dir = Path("/var/lib/kubelet/checkpoints")
    tars = sorted(src_dir.glob("*.tar"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not tars:
        print("    [!] no checkpoint .tar found in /var/lib/kubelet/checkpoints")
        return None
    latest = tars[0]
    storage = Path(args.storage); storage.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    dst = storage / f"{args.pod}-{ts}.tar"
    shutil.move(str(latest), dst)
    try:
        dst.chmod(0o644)   # so the non-root user can read it for analysis
    except Exception:
        pass
    print(f"    [offload] {latest.name} -> {dst}")
    return dst


def kill_pod(args):
    print(f"    [kill] deleting pod {args.pod}")
    sh(["kubectl", "delete", "pod", args.pod, "-n", args.namespace, "--wait=false"])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--namespace", default="default")
    ap.add_argument("--pod", required=True)
    ap.add_argument("--container", required=True)
    ap.add_argument("--threshold", type=float, default=0.70)
    ap.add_argument("--interval", type=float, default=3.0)
    ap.add_argument("--storage", default="./memory-images")
    ap.add_argument("--kubelet-host", default="localhost")
    ap.add_argument("--kubelet-port", default="10250")
    ap.add_argument("--key", default="/etc/kubernetes/pki/apiserver-kubelet-client.key")
    ap.add_argument("--cert", default="/etc/kubernetes/pki/apiserver-kubelet-client.crt")
    ap.add_argument("--cacert", default="/etc/kubernetes/pki/ca.crt")
    ap.add_argument("--no-kill", action="store_true", help="checkpoint+offload but don't delete")
    args = ap.parse_args()

    print(f"[watcher] monitoring {args.namespace}/{args.pod} "
          f"(threshold={args.threshold}, every {args.interval}s)")
    while True:
        risk, sig = compute_risk(args.namespace, args.pod, args.container)
        stamp = datetime.now().strftime("%H:%M:%S")
        print(f"{stamp}  risk={risk:<5} {sig}")
        if "error" in sig:
            print("[watcher] pod gone — exiting")
            return
        if risk >= args.threshold:
            print(f"[watcher] THRESHOLD CROSSED (risk={risk}) — capturing")
            if checkpoint(args):
                offload(args)
                if not args.no_kill:
                    kill_pod(args)
            print("[watcher] capture complete — exiting")
            return
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
