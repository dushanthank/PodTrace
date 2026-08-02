# PodTrace

Checkpoint-driven Kubernetes forensics system with ML-assisted malware triage.

When a pod behaves suspiciously, PodTrace freezes it with CRIU, extracts five
categories of memory-only artefacts, classifies every ELF binary with a trained
XGBoost model, and produces a ranked HTML + JSON incident report — all before the
pod is torn down and the evidence is lost.

---

## Prerequisites

### 1. Virtual Machine

- **Hypervisor:** Oracle VirtualBox 7.2 (or any Type-2 hypervisor)
- **OS:** Ubuntu 24.04.4 LTS
- **RAM:** 8 GB minimum (16 GB recommended — CRIU checkpoints can be several GB)
- **Storage:** 50 GB minimum (room for the OS, container images, checkpoints, and ELF dataset)
- **Network:** Host-only or NAT adapter; internet access required during setup only

### 2. Software stack (installed on the VM)

| Component | Version used |
|---|---|
| Kubernetes (kubeadm single-node) | v1.36.0 |
| containerd | v2.2.1 |
| CRIU | v4.2 |
| CNI plugin | Flannel v0.28.4 |
| Python | 3.11+ |
| pip packages | see `analyzer/requirements.txt` |

### 3. Kubernetes setup notes

- Single-node cluster — control-plane node is also the worker node
- `kubectl top` (metrics-server) must be enabled for the watcher's memory readings
- The kubelet checkpoint API (`POST https://node:10250/checkpoint/...`) requires mTLS — use the admin client cert from `/etc/kubernetes/admin.conf`

---

## Repository layout

```
PodTrace/
├── analyzer/                   # Offline analysis pipeline
│   ├── analyze_checkpoint.py   # Main entry point — runs the full 7-step pipeline
│   ├── artifacts.py            # Memory-only artefact recovery (network, secrets, etc.)
│   ├── explain.py              # SHAP explainability for the ELF classifier
│   ├── threat_scoring.py       # Unified threat scoring and MITRE ATT&CK tagging
│   ├── requirements.txt        # Python dependencies
│   ├── features/
│   │   ├── elf_features.py     # Static ELF feature extraction (40+ features)
│   │   └── command_features.py # Rule/IOC layer for shell command scoring
│   ├── data/                   # Dataset collection and preparation scripts
│   │   ├── build_dataset.py    # Builds the labelled feature matrix from ELF samples
│   │   ├── collect_benign.py   # Harvests benign ELF binaries from containers / host
│   │   ├── collect_malware.py  # Downloads malware samples from MalwareBazaar
│   │   └── make_synthetic.py   # Generates a smoke-test dataset (no real malware needed)
│   ├── datasets/
│   │   └── commands.csv        # Labelled command dataset for the command classifier
│   └── train/
│       ├── train_file_clf.py   # Trains the XGBoost ELF classifier
│       ├── train_command_clf.py# Trains the TF-IDF command classifier
│       ├── evaluate.py         # Confusion matrix, ROC-AUC, F1 on the held-out test set
│       └── benchmark.py        # Benchmarks all six candidate ML models side by side
│
├── podtrace/                   # Watcher and demo scripts
│   ├── watcher.py              # Manual watcher (run on the node, uses kubectl)
│   ├── watcher_incluster.py    # In-cluster DaemonSet agent
│   ├── plant_artifacts.sh      # Full attack simulation (high score demo)
│   ├── plant_artifacts_medium.sh # Mid-severity demo (~75/100 High)
│   └── ddos_flood.py           # HTTP + memory pressure flood to trigger the watcher
│
└── deploy/                     # Kubernetes manifests
    ├── 01-namespace-rbac.yaml  # Namespace, ServiceAccount, ClusterRole for the DaemonSet
    ├── 02-daemonset.yaml       # PodTrace watcher DaemonSet
    └── webserver.yaml          # Demo nginx target pod
```

---

## What each file does

**`analyze_checkpoint.py`** — The main script you run on a checkpoint archive. It extracts the CRIU `.tar`, unpacks the container filesystem, reconstructs command history from three sources (bash history, process table, RAM page carving), scores every ELF binary with the ML model, scores commands with a hybrid rule + ML scorer, carves five categories of memory-only artefacts, and writes `report.html` + `report.json`.

**`artifacts.py`** — Parses the raw CRIU image files to recover artefacts that only exist in memory: live network connections (from `inetsk.img`), anonymous RWX memory regions indicating injected code (from `mm-*.img`), executables deleted from disk but still running (from `reg-files.img`), the full process tree (from `pstree.img`), and in-memory credentials carved from raw `pages-*.img`.

**`explain.py`** — Wraps SHAP's `TreeExplainer` to produce per-file explanations. For every file the classifier flags, it reports the top features that pushed the verdict toward malicious with their signed SHAP values — so the analyst can see exactly why the model made its call, not just a score.

**`threat_scoring.py`** — Converts raw ML scores into a 0–100 threat score, applies forensic context multipliers (files in `/tmp` score higher, RAM-resident commands score higher), tags every finding with MITRE ATT&CK technique IDs, and computes the overall `incident_risk` score shown at the top of the report.

**`features/elf_features.py`** — Extracts 40+ static features from an ELF binary: segment counts, section entropy, imported library names, suspicious string tokens (bot family names, dropper IPs), packer signatures, and a byte-frequency histogram. These are the features the XGBoost model was trained on.

**`features/command_features.py`** — Rule/IOC layer for shell commands. Contains a hand-written set of high-precision regex rules (download piped to shell, netcat reverse shell, known DDoS tools, etc.) with assigned weights. Also provides the tokeniser used by the TF-IDF command model.

**`data/build_dataset.py`** — Walks the benign and malware ELF directories, extracts features for every sample, labels them 0/1, and writes `features.parquet` plus stratified `train.parquet` / `test.parquet` splits.

**`data/collect_benign.py`** — Collects benign ELF binaries for training either from a container image export or from the host filesystem (`/usr/bin`, `/bin`, `/usr/sbin`). Used to build the benign class.

**`data/collect_malware.py`** — Downloads confirmed malicious Linux ELF samples from MalwareBazaar targeting DDoS bot families (Mirai, Gafgyt, Tsunami, XorDDoS). Stores them inert inside password-protected ZIPs for static feature extraction only. **Never executed.**

**`data/make_synthetic.py`** — Generates a smoke-test dataset without real malware by mutating benign ELFs to look structurally like droppers (high-entropy appended blob, suspicious string tokens). Useful for validating the full pipeline before wiring in real data.

**`datasets/commands.csv`** — Labelled shell command dataset (`text, label`). Benign commands from normal shell history and NL2Bash; malicious commands from Cowrie honeypot logs and known dropper/flood one-liners. Training data for the command classifier.

**`train/train_file_clf.py`** — Trains the ELF binary classifier. Benchmarks XGBoost and RandomForest, picks the best by cross-validated ROC-AUC, and saves the fitted model as `models/file_clf.joblib`.

**`train/train_command_clf.py`** — Trains the command classifier: TF-IDF (word + char n-grams) → Logistic Regression pipeline, saved as `models/command_clf.joblib`.

**`train/evaluate.py`** — Loads the held-out test set and the saved model, prints the confusion matrix, ROC-AUC, precision, recall, and F1, and writes `eval_metrics.json`.

**`train/benchmark.py`** — Trains and cross-validates six candidate models (XGBoost, Random Forest, Extra Trees, Gradient Boosting, Logistic Regression, SVM-RBF) side by side and writes `benchmark_table.md` for the dissertation.

**`watcher.py`** — The manual watcher. Polls a target pod every 3 seconds, computes a risk score from memory pressure, restart count, OOM events, and readiness state, and triggers a CRIU checkpoint via the Kubelet API when the score exceeds the threshold.

**`watcher_incluster.py`** — The production version of the watcher packaged as a Kubernetes DaemonSet agent. Runs inside the cluster, uses the in-cluster service account, and writes checkpoints to a hostPath volume.

**`plant_artifacts.sh`** — Full attack simulation script for the demo. Plants a malicious ELF binary, adversarial shell commands, background processes, and credential strings inside the target pod to produce a 100/100 Critical report.

**`plant_artifacts_medium.sh`** — Mid-severity demo script. Plants only suspicious `wget` and `nc` commands in the pod's bash history (no malicious binary) to produce a ~75/100 High report, demonstrating the scoring range below Critical.

**`ddos_flood.py`** — Sends a high volume of concurrent HTTP requests to the nginx service and optionally triggers in-pod memory pressure to push the watcher's risk score over the threshold naturally.

**`deploy/01-namespace-rbac.yaml`** — Creates the `podtrace` namespace and the ServiceAccount + ClusterRole needed for the DaemonSet to read pod metrics and call the Kubelet checkpoint API.

**`deploy/02-daemonset.yaml`** — Deploys the PodTrace watcher as a DaemonSet so it runs on every node in the cluster.

**`deploy/webserver.yaml`** — The demo nginx target pod with a memory limit set low enough for the memory fill to trigger the watcher.

---

## Generating the trained models

The `models/` directory is not committed to this repository because the model files are binary and require the ELF dataset to produce. To generate them:

```bash
cd analyzer

# Step 1 — collect benign ELF binaries from the host filesystem
python3 data/collect_benign.py --source host --out datasets/benign

# Step 2 — build the labelled feature matrix
python3 data/build_dataset.py \
    --benign datasets/benign \
    --malware datasets/malware/inert \
    --out datasets

# Step 3 — train the ELF file classifier
python3 train/train_file_clf.py --data datasets --out models

# Step 4 — train the command classifier
python3 train/train_command_clf.py --csv datasets/commands.csv --out models

# Step 5 — evaluate on the held-out test set
python3 train/evaluate.py --data datasets --model models/file_clf.joblib --out reports
```

This produces `models/file_clf.joblib` and `models/command_clf.joblib`, which the analyser loads at runtime.

The malware samples for Step 2 were downloaded from [MalwareBazaar](https://bazaar.abuse.ch) using `data/collect_malware.py` inside an isolated research VM with no outbound network access to the rest of the network.

---

### `samples/*.elf` and `datasets/malware/`

These are confirmed malicious Linux binaries (Mirai, Gafgyt, Tsunami, XorDDoS variants) downloaded from MalwareBazaar. They are excluded because:

- MalwareBazaar's Terms of Service prohibit redistribution of samples
- Committing live malware to a public repository is irresponsible regardless of intent
- They are large binary files with no place in version control

Only the SHA-256 hashes of the samples used are reported in the dissertation. To reproduce the dataset, use `data/collect_malware.py` with your own MalwareBazaar API key inside an isolated VM.

### `datasets/benign/*.elf`

Benign ELF binaries harvested from container images and the host filesystem are also excluded. They are standard Linux system binaries (coreutils, nginx, etc.) and are large in aggregate. Run `data/collect_benign.py` to regenerate them.

---

## Running the analyser

```bash
cd analyzer
pip install -r requirements.txt

python3 analyze_checkpoint.py \
    --checkpoint /path/to/checkpoint.tar \
    --models models \
    --out reports/incident-001 \
    --pod webserver
```

Open `reports/incident-001/report.html` in a browser.

---

## End-to-end walkthrough

This section covers everything from a fresh Ubuntu VM to a working forensic report.

### Phase 1 — Provision the VM

1. Create a new VM in VirtualBox with Ubuntu 24.04.4 LTS, 8 GB RAM, and 50 GB storage.
2. Boot from the ISO, complete the standard Ubuntu installation.
3. Install guest additions if you want shared folders between host and VM.

### Phase 2 — Install the software stack

```bash
# Update the system
sudo apt update && sudo apt upgrade -y

# Container runtime (containerd)
sudo apt install -y containerd
sudo mkdir -p /etc/containerd
containerd config default | sudo tee /etc/containerd/config.toml
sudo systemctl restart containerd && sudo systemctl enable containerd

# CRIU (memory checkpoint tool)
sudo apt install -y criu

# kubeadm, kubelet, kubectl
sudo apt install -y apt-transport-https ca-certificates curl
curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.36/deb/Release.key \
  | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.36/deb/ /' \
  | sudo tee /etc/apt/sources.list.d/kubernetes.list
sudo apt update && sudo apt install -y kubelet kubeadm kubectl
sudo apt-mark hold kubelet kubeadm kubectl

# Python dependencies
sudo apt install -y python3-pip python3-venv
```

### Phase 3 — Bootstrap the Kubernetes cluster

```bash
# Disable swap (required by kubelet)
sudo swapoff -a
sudo sed -i '/ swap / s/^/#/' /etc/fstab

# Initialise the single-node cluster
sudo kubeadm init --pod-network-cidr=10.244.0.0/16

# Configure kubectl for your user
mkdir -p $HOME/.kube
sudo cp /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config

# Allow scheduling on the control-plane node (single-node setup)
kubectl taint nodes --all node-role.kubernetes.io/control-plane-

# Install the Flannel CNI plugin
kubectl apply -f https://github.com/flannel-io/flannel/releases/download/v0.28.4/kube-flannel.yml

# Install metrics-server (required for kubectl top / watcher memory readings)
kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml

# Verify the node is Ready (may take ~60s)
kubectl get nodes
```

### Phase 4 — Clone the repository and set up Python

```bash
git clone https://github.com/<your-username>/PodTrace.git
cd PodTrace/analyzer

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Phase 5 — Build the dataset and train the models

```bash
# Inside PodTrace/analyzer/ with the venv active

# 5a. Collect benign ELF binaries from the host filesystem
python3 data/collect_benign.py --source host --out datasets/benign

# 5b. Collect malware samples from MalwareBazaar (isolated VM only)
#     Requires a free API key from https://bazaar.abuse.ch/account/
export MB_API_KEY=your_key_here
python3 data/collect_malware.py \
    --out datasets/malware \
    --tags Mirai Gafgyt Tsunami \
    --limit 100

# 5c. Build the labelled feature matrix
python3 data/build_dataset.py \
    --benign datasets/benign \
    --malware datasets/malware/inert \
    --out datasets

# 5d. Train the ELF file classifier
python3 train/train_file_clf.py --data datasets --out models

# 5e. Train the command classifier
python3 train/train_command_clf.py --csv datasets/commands.csv --out models

# 5f. Evaluate on the held-out test set
python3 train/evaluate.py --data datasets --model models/file_clf.joblib --out reports

# 5g. (Optional) Benchmark all six candidate models
python3 train/benchmark.py --data datasets --out reports
```

After this step, `models/file_clf.joblib` and `models/command_clf.joblib` exist and the analyser is ready.

> **Skip 5b if you don't have a MalwareBazaar key.** Run `python3 data/make_synthetic.py --out datasets` instead to generate a synthetic dataset for smoke-testing the pipeline. Real accuracy numbers require real malware samples.

### Phase 6 — Deploy the demo environment

```bash
cd PodTrace  # back to repo root

# 6a. Create the namespace, RBAC, and checkpoint storage directory
kubectl apply -f deploy/01-namespace-rbac.yaml
sudo mkdir -p /opt/podtrace/memory-images
sudo chmod 777 /opt/podtrace/memory-images

# 6b. Deploy the PodTrace watcher DaemonSet
kubectl apply -f deploy/02-daemonset.yaml

# 6c. Deploy the demo nginx target pod
kubectl apply -f deploy/webserver.yaml

# Verify everything is running
kubectl get pods -A
```

### Phase 7 — Run a demo scenario

Three scenarios to demonstrate the scoring range:

**Scenario A — Clean pod (expected score: 0/100 Low)**

No attack script. Just wait for the watcher to trigger naturally (memory fill via the pod's readiness probe eventually causes the watcher to capture it), or checkpoint manually:

```bash
# Manual checkpoint via kubelet API
NODE=$(kubectl get node -o jsonpath='{.items[0].metadata.name}')
CERT=$(kubectl config view --raw -o jsonpath='{.users[0].user.client-certificate-data}' | base64 -d)
KEY=$(kubectl config view --raw -o jsonpath='{.users[0].user.client-key-data}' | base64 -d)
curl -sk --cert <(echo "$CERT") --key <(echo "$KEY") \
  -X POST "https://localhost:10250/checkpoint/default/webserver/webserver"
```

**Scenario B — Mid-severity (expected score: ~75/100 High)**

```bash
./podtrace/plant_artifacts_medium.sh webserver default
# Wait ~30s for the watcher to trigger, then analyse the new .tar
```

**Scenario C — Full attack (expected score: 100/100 Critical)**

```bash
./podtrace/plant_artifacts.sh webserver default ./samples/mirai_sample.elf
# Wait ~30s for the watcher to trigger, then analyse the new .tar
```

### Phase 8 — Analyse the checkpoint

```bash
cd analyzer
source .venv/bin/activate

# List available checkpoints
ls /opt/podtrace/memory-images/

# Run the analyser on the most recent checkpoint
python3 analyze_checkpoint.py \
    --checkpoint /opt/podtrace/memory-images/<checkpoint-name>.tar \
    --models models \
    --out reports/incident-001 \
    --pod webserver

# Open the report
xdg-open reports/incident-001/report.html
```

The report ranks every finding worst-first, shows MITRE ATT&CK tags, SHAP explanations for flagged ELF binaries, and lists all five categories of memory-only artefacts.
