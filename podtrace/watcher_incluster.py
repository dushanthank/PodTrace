#!/usr/bin/env python3
"""
PodTrace in-cluster agent (runs INSIDE the cluster, deployed via YAML as a
DaemonSet). It continuously scores the crash-risk of target pods and, when a pod
is about to die, auto-triggers memory-image collection and saves the image to the
Ubuntu host.

Why a node DaemonSet (not a sidecar): checkpointing requires the node's kubelet
client certs, host access to /var/lib/kubelet/checkpoints, and a hostPath on the
node to persist the image. A DaemonSet on the node has all three; a sidecar in the
app pod does not.

Flow per interval:
    1. read target pod(s) + memory usage (metrics.k8s.io) + status
    2. compute risk score
    3. if risk >= threshold:
         a. POST kubelet /checkpoint/<ns>/<pod>/<container>   (container stays up)
         b. move the resulting .tar from /var/lib/kubelet/checkpoints -> SAVE_DIR
            (SAVE_DIR is a hostPath -> a real directory on the Ubuntu machine)
         c. delete the pod

Configuration is via environment variables (set in the DaemonSet):
    TARGET_NAMESPACE   (default "default")
    TARGET_POD         exact pod name         (optional)
    TARGET_LABEL       label selector e.g. app=web  (optional; used if TARGET_POD unset)
    CONTAINER          container name to checkpoint
    THRESHOLD          risk threshold          (default 0.60)
    INTERVAL           seconds between polls    (default 3)
    KUBELET_HOST       (default 127.0.0.1)      NODE_IP works via hostNetwork
    KUBELET_PORT       (default 10250)
    SAVE_DIR           where to persist images  (default /savedir -> hostPath)
    KUBELET_KEY/CERT/CACERT  paths to mounted kubelet client certs
    CAPTURE_PREEXISTING  "true" to also capture pods already high at startup
                         (default "false" = only capture on an observed rise)
"""
import os
import re
import shutil
import time
from datetime import datetime
from pathlib import Path

import requests
import urllib3
from kubernetes import client, config

# kubelet's serving cert is self-signed (not signed by the cluster CA), so we skip
# server-cert verification exactly like `curl -sk`. Client cert auth is still sent.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

MEM_UNITS = {"Ki": 1024, "Mi": 1024**2, "Gi": 1024**3,
             "K": 1000, "M": 1000**2, "G": 1000**3, "n": 1e-9, "u": 1e-6, "m": 1e-3, "": 1}


def env(k, d=None):
    return os.environ.get(k, d)


def parse_qty(v: str) -> float:
    m = re.match(r"([0-9.]+)([A-Za-z]*)", str(v).strip())
    return float(m.group(1)) * MEM_UNITS.get(m.group(2), 1) if m else 0.0


class Agent:
    def __init__(self):
        config.load_incluster_config()
        self.core = client.CoreV1Api()
        self.custom = client.CustomObjectsApi()
        self.ns = env("TARGET_NAMESPACE", "default")
        self.pod_name = env("TARGET_POD")
        self.label = env("TARGET_LABEL")
        self.container = env("CONTAINER", "")
        self.threshold = float(env("THRESHOLD", "0.60"))
        self.interval = float(env("INTERVAL", "3"))
        self.khost = env("KUBELET_HOST", "127.0.0.1")
        self.kport = env("KUBELET_PORT", "10250")
        self.save_dir = Path(env("SAVE_DIR", "/savedir"))
        self.certs = (env("KUBELET_CERT", "/certs/apiserver-kubelet-client.crt"),
                      env("KUBELET_KEY", "/certs/apiserver-kubelet-client.key"))
        self.cacert = env("KUBELET_CACERT", "/certs/ca.crt")
        # only capture on a RISING edge: a pod must be seen healthy (below threshold)
        # at least once before it's eligible, so we never fire on a pod that was
        # already high when monitoring started (leftover memory / stale metrics).
        self.capture_preexisting = env("CAPTURE_PREEXISTING", "false").lower() == "true"
        self.captured = set()   # uids already captured
        self.armed = set()      # uids observed healthy at least once

    def targets(self):
        if self.pod_name:
            try:
                return [self.core.read_namespaced_pod(self.pod_name, self.ns)]
            except Exception:
                return []
        pods = self.core.list_namespaced_pod(self.ns, label_selector=self.label)
        return pods.items

    def mem_usage(self, pod: str) -> float:
        try:
            m = self.custom.get_namespaced_custom_object(
                "metrics.k8s.io", "v1beta1", self.ns, "pods", pod)
            return sum(parse_qty(c["usage"]["memory"]) for c in m.get("containers", []))
        except Exception:
            return 0.0

    def risk(self, pod) -> tuple[float, dict]:
        name = pod.metadata.name
        container = self.container or pod.spec.containers[0].name
        limit = 0.0
        for c in pod.spec.containers:
            if c.name == container and c.resources and c.resources.limits:
                limit = parse_qty(c.resources.limits.get("memory", "0"))
        usage = self.mem_usage(name)
        ratio = usage / limit if limit else 0.0
        restarts = oom = notready = 0
        for cs in (pod.status.container_statuses or []):
            if cs.name == container:
                restarts = cs.restart_count or 0
                if cs.last_state and cs.last_state.terminated and \
                        cs.last_state.terminated.reason == "OOMKilled":
                    oom = 1
                if not cs.ready:
                    notready = 1
        # memory can trip the trigger on its own (ratio ~0.85 -> ~0.77, +not_ready -> >0.9)
        score = min(1.0, 0.90 * min(ratio, 1.0) + 0.20 * min(restarts / 3.0, 1.0)
                    + 0.25 * oom + 0.15 * notready)
        return round(score, 3), {"mem_ratio": round(ratio, 3), "restarts": restarts,
                                 "oom": oom, "not_ready": notready,
                                 "usage_mb": round(usage / 1e6, 1)}

    def checkpoint(self, pod: str, container: str) -> bool:
        url = f"https://{self.khost}:{self.kport}/checkpoint/{self.ns}/{pod}/{container}"
        print(f"    [checkpoint] POST {url}", flush=True)
        try:
            r = requests.post(url, cert=self.certs, verify=False, timeout=120)
            print(f"    [checkpoint] {r.status_code}: {r.text[:200]}", flush=True)
            return r.status_code == 200
        except Exception as e:
            print(f"    [!] checkpoint error: {e}", flush=True)
            return False

    def offload(self, pod: str):
        src = Path("/var/lib/kubelet/checkpoints")
        # prefer a tar whose name matches THIS pod (kubelet names it
        # checkpoint-<pod>_<ns>-<container>-<ts>.tar); fall back to newest overall
        tars = sorted(src.glob(f"checkpoint-{pod}_*.tar"),
                      key=lambda p: p.stat().st_mtime, reverse=True)
        if not tars:
            tars = sorted(src.glob("*.tar"), key=lambda p: p.stat().st_mtime, reverse=True)
        if not tars:
            print("    [!] no checkpoint tar found", flush=True)
            return
        self.save_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        dst = self.save_dir / f"{pod}-{ts}.tar"
        shutil.move(str(tars[0]), dst)
        try:
            dst.chmod(0o644)   # so the non-root user can read it for analysis
        except Exception:
            pass
        print(f"    [offload] saved -> {dst}", flush=True)

    def kill(self, pod: str):
        print(f"    [kill] deleting pod {pod}", flush=True)
        try:
            self.core.delete_namespaced_pod(pod, self.ns, grace_period_seconds=0)
        except Exception as e:
            print(f"    [!] delete error: {e}", flush=True)

    def loop(self):
        print(f"[agent] watching ns={self.ns} pod={self.pod_name or self.label} "
              f"threshold={self.threshold}", flush=True)
        while True:
            for pod in self.targets():
                name = pod.metadata.name
                uid = pod.metadata.uid           # unique per pod instance
                if uid in self.captured:
                    continue
                container = self.container or pod.spec.containers[0].name
                score, sig = self.risk(pod)
                print(f"{datetime.now():%H:%M:%S}  {name} risk={score} {sig}", flush=True)

                if score < self.threshold:
                    self.armed.add(uid)          # seen healthy -> eligible to trigger later
                    continue

                # score >= threshold: only fire if we saw this pod healthy first
                if uid not in self.armed and not self.capture_preexisting:
                    print(f"    [skip] {name} was already high when first observed "
                          f"(pre-existing/stale state) — waiting for a real rise", flush=True)
                    continue

                print(f"[agent] THRESHOLD CROSSED for {name} — capturing", flush=True)
                if self.checkpoint(name, container):
                    self.offload(name)
                    self.kill(name)
                    self.captured.add(uid)       # only stop retrying once it worked
                else:
                    print("    [!] checkpoint failed — will retry next interval", flush=True)
            time.sleep(self.interval)


if __name__ == "__main__":
    Agent().loop()
