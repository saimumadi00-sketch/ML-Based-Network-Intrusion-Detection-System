# NIDS-Agent: ML-Based Network Intrusion Detection

A network intrusion detection system that scores every connection Zeek sees with a trained random-forest classifier, adds rule-based and statistical detection, and emits explainable, privacy-safe alerts with MITRE ATT&CK mapping, a chain-of-custody decision log, and Prometheus metrics.

- **Detects** port scans, DoS/DDoS, and FTP/SSH brute force with ≥95% recall at 0.57% false alarms on held-out CIC-IDS2017 traffic (numbers and limits below).
- **Runs anywhere Python runs:** the runtime is pure standard library, so it has no dependencies to install or patch. The model ships as gzipped JSON (no pickle, so loading it cannot execute code).
- **Built for continuous operation:** a resumable file follower that survives Zeek log rotation, at-least-once delivery, a dead-letter queue, health checks, bounded disk use, and graceful shutdown.

```
 network ──► Zeek ──► conn.log ──► NIDS service ─┬─► alerts.jsonl   (text + structured fields, for a SIEM)
                                    │            ├─► decision_log.jsonl (every step, every flow)
                                    │            ├─► responses.jsonl (opt-in autonomous actions)
                                    │            └─► /healthz, /metrics (Prometheus)
                                    ▼
      preprocess → rules + port-scan aggregation → z-score anomaly → random forest
      → classification → 24 h correlation + MITRE → CVSS-style severity → alert / response
```

## Quick start

```bash
# One batch from a file (JSONL, CSV, or Zeek conn.log)
python app.py --input data/sample_flows.jsonl
python app.py --input /opt/zeek/logs/current/conn.log --format zeek

# Continuous service on Zeek's live log
python app.py --serve --follow /opt/zeek/logs/current/conn.log --format zeek --metrics-port 9108
curl -s localhost:9108/healthz
```

Requires Python 3.10+. Nothing to install for detection; `requirements-train.txt` (numpy, scikit-learn) is only needed to retrain.

## Deploy

**Docker Compose (Zeek + NIDS, Linux):**

```bash
NIDS_IFACE=eth0 docker compose up -d     # Zeek sniffs eth0; the NIDS follows its conn.log
docker compose logs -f nids              # alerts are printed as they fire
curl -s localhost:9108/metrics
```

Detect-only by default. Alerts and state live in the `nids-logs` volume.

**systemd next to an existing zeekctl install:** `infra/systemd/nids.service` (non-root user, sandboxed, state in `/var/lib/nids`). Install steps are in the file header.

**Other sources:** `--follow -` reads stdin, so anything that produces conn.log or JSONL lines can feed it (for example `zeek-cut`, `kafkacat`, or `redis-cli`). Capture, NetFlow and streaming setup notes are in `infra/`.

Before relying on it, run it in detect-only mode on your own traffic for a while and measure false alarms there (see [Limits](#limits)).

## Operating it

| Concern | Behaviour |
|---|---|
| Restart / crash | Checkpoint (inode + byte offset) is saved after each batch; a restart resumes there. At-least-once: a crash re-processes at most one batch. Re-processed flows are not recorded twice. |
| Zeek log rotation | Followed like `tail -F`: drains the old file, then opens the new one; truncation restarts at 0. |
| Bad input / bugs | A batch that raises goes to `dead_letter.jsonl` and the service keeps going. `/healthz` returns 503 after 3 failed batches in a row. |
| Shutdown | SIGTERM/SIGINT finish the current batch, save the checkpoint, exit 0. |
| Disk | Each JSONL log rotates at `NIDS_LOG_MAX_BYTES` (default 100 MB), keeping `NIDS_LOG_BACKUPS` (default 5) old files: at most ~600 MB per log. State files are written atomically. |
| Alert volume | A port scan raises one alert per source per 5 minutes (`Config.scan_alert_cooldown_seconds`); every probe is still in the decision log and event history. |
| SIEM | Each `alerts.jsonl` record has `fields` (severity, incident_id, attack_type, mitre, source/target ip and port, action) next to the human-readable alert. |
| Monitoring | `/metrics`: flows, batches, batch errors, alerts by severity, last batch latency and age, source lag, `nids_up`. Bound to 127.0.0.1 unless `--metrics-host` is set. |
| Throughput | About 1,800 flows/s on one core (30k synthetic flows via stdin, Windows, Python 3.14). Above that, run one instance per Zeek worker or per source. |

Reports from the logs:

```bash
python app.py --report incident_report --hours 24   # incidents by severity/type, escalations, responses
python app.py --report hourly_summary               # volume, latency, recall/FPR (if labelled), drift
python app.py --report daily_digest
```

## Configuration

| Option | Default | Purpose |
|---|---|---|
| `--logs-dir` | `logs` | Alerts, decision log, checkpoint, state |
| `--baseline` | `data/models/baseline.json` | Benign traffic profile for z-scores and drift (fit your own with `--fit-baseline OUT --input benign.jsonl`) |
| `--asset-map` | none | `{"203.0.113.10": {"asset_tag": "web-01", "criticality": "CRITICAL"}}` raises severity for critical assets |
| `--authorize` | off | Allow autonomous responses: `HIGH` → rate-limit, `CRITICAL` → block the source. Never for escalated incidents or internal sources. Every decision, including skips, is logged. |
| `--batch-size` / `--max-wait` | 500 / 2 s | Micro-batch size, or flush what has arrived after N seconds |
| `--from-start` | off | Read the followed file from the beginning (default: only new lines unless a checkpoint exists) |
| `NIDS_LOG_MAX_BYTES` / `NIDS_LOG_BACKUPS` | 100 MB / 5 | Log rotation; `NIDS_LOG_MAX_BYTES=0` disables it |

Detection rules, MITRE mapping, severity weights, response actions and thresholds are in `nids_agent/config.py`.

**Privacy:** internal addresses (RFC 1918, loopback, link-local, IPv6 ULA) and asset tags are redacted in alerts; no payload is read or logged.

## Detection results

The default model, `data/models/flow_classifier.json.gz`, is a random forest trained on what production sees: Zeek `conn.log` generated from the CIC-IDS2017 packet captures (Tuesday–Friday, 1.74M connections). Labels come from CIC's TrafficLabelling CSVs, matched by endpoints, protocol and time (99.2–99.5% of TCP/UDP connections matched per day).

Held-out connections (connection-level split; the full pipeline is scored on test connections only, with the rules still seeing all traffic in time order):

| | Attacks caught | False alarms | Precision |
|---|---|---|---|
| Model only | 94.7% | 0.47% | 98.9% |
| Rules only (port-scan aggregation, DoS signatures) | 43.2% | 0.19% | 99.0% |
| **Full pipeline** | **94.9%** | **0.57%** | **98.7%** |

- **Caught well (≥95%):** port scan (100%), DDoS (99.9%), DoS Hulk/GoldenEye/slowloris, FTP and SSH brute force (≥99.8%). The infiltration victim's internal scan: 90.5%.
- **Not caught:** web attacks (XSS 3%, web brute force 9%), Bot (28%), DoS Slowhttptest (27%). Many of these connections have exactly the same flow statistics as benign ones, so no flow-level model can separate them; they need HTTP/DNS-level features.
- **Unseen feature vectors:** on test connections whose feature vector never occurs in training, the model catches 97.7% at 0.49% false alarms.
- **Label correction:** on Thursday 14:19–15:45 the infiltration victim (192.168.10.8) port-scans the internal network, and CIC labels those flows BENIGN (a documented CIC-IDS2017 labeling issue). Training and the scores above relabel them (`eval_zeek.KNOWN_LABEL_ERRORS`). With CIC's labels as published, the pipeline's false-alarm rate reads 6.0%, nearly all of it this scan.
- Full numbers: `data/models/flow_classifier.metrics.json` (model), `flow_classifier.pipeline_eval.json` (pipeline, per class).

**Why train on Zeek output and not the CICFlowMeter CSVs?** A model trained on the CSVs did not transfer: CICFlowMeter counts Ethernet padding as payload, so a SYN→RST probe has 6 response bytes in the CSVs but 0 in Zeek. That model caught 99.9% of Friday's port scans on CSV features and 3.5% on Zeek output. It is kept as `flow_classifier_cicflowmeter.json.gz` for CICFlowMeter input only (`Config(ml_model_name="flow_classifier_cicflowmeter")` with `--baseline data/models/baseline_cicflowmeter.json`; 99.6% recall, 0.43% FPR on its own held-out CSV flows).

### How the decision is made

1. **Features** (`nids_agent/features.py`, shared by training and inference): destination port, duration, packets and bytes in each direction, inter-arrival time mean/std when present, and derived rates and ratios. All exist in Zeek, NetFlow and CICFlowMeter output.
2. **Model**: `ForestModel` (`nids_agent/model.py`) walks the exported trees in plain Python, matching scikit-learn's output to within 1e-6. The ATTACK threshold was chosen on a validation split for ≤0.5% false positives. ICMP is not scored (outside the training data).
3. **Rules**: per-flow DoS/DDoS signatures, plus port-scan aggregation per source (≥10 distinct targets from SYN probes that get no payload back, within 60 s, across batches).
4. **Anomaly**: z-scores against the benign baseline. A trained model's BENIGN verdict is final; the z-scores remain as alert evidence. On top of the model they added 1.6 points of false positives and no recall.
5. **Classification, correlation, severity**: category and subtype with confidences (below 0.65 → escalate to a human), related events from the last 24 h, MITRE ATT&CK technique, CVSS-style score weighted by asset criticality.

### Reproduce / retrain

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-train.txt
# CIC-IDS2017 PCAPs -> Zeek conn.log (needs Zeek; ~1.5 h streaming for 4 days; PCAPs are not stored)
for d in Tuesday-WorkingHours Wednesday-workingHours Thursday-WorkingHours Friday-WorkingHours; do
  scripts/zeek_cic_pcap.sh $d datasets/cicids2017/zeek; done
# GeneratedLabelledFlows.zip (sha256 7bdbef28...a27a) -> "datasets/cicids2017/TrafficLabelling /"
.venv/bin/python scripts/train_zeek_model.py datasets/cicids2017/zeek "datasets/cicids2017/TrafficLabelling "
python3 scripts/eval_zeek.py datasets/cicids2017/zeek/Friday-WorkingHours.conn.log \
    "datasets/cicids2017/TrafficLabelling /Friday-*.csv" --only-uids datasets/cicids2017/zeek/test_uids.txt --fix-known-label-errors
# CICFlowMeter model: scripts/train_model.py datasets/cicids2017/MachineLearningCVE --out data/models/flow_classifier_cicflowmeter.json.gz
```

## Limits

- **One dataset.** All accuracy figures come from CIC-IDS2017: lab traffic from 2017, one network, one week, with known labeling errors. A random split also puts connections from the same attack sessions in train and test. Expect lower accuracy on your network; measure it there in detect-only mode.
- **Flow-level blind spots.** Web attacks, bots and low-and-slow DoS are mostly missed (see above).
- **Responses are recorded, not enforced.** `execute_response` writes `responses.jsonl`; connecting it to a firewall, Zeek NetControl or a SOAR is deployment-specific and not done.
- **Threat intel and flow DB are local samples** (`data/threat_intel.json`, `data/flow_db.jsonl`), not live feeds.
- **Reports read only the current log file**, not rotated ones.
- **Single process.** Correlation history (24 h, newest 1,000 events) and scan state are per instance.

## Roadmap

1. Validate on a second dataset (UNSW-NB15 or CIC-IDS2018) and a cross-day split (train Tue–Thu, test Fri); cross-dataset numbers are the honest estimate.
2. Add application-layer features from Zeek `http.log` / `dns.log` for web attacks and bots.
3. Wire `execute_response` to an enforcement point (firewall API or Zeek NetControl) behind the existing authorization gate.
4. Live threat-intel feed (for example MISP or abuse.ch) in place of the local sample.
5. Shared state (Redis) so several instances can correlate across Zeek workers.

## Project layout

```
app.py                     CLI: batch, service, reports, baseline fitting
nids_agent/
  engine.py                pipeline orchestration (one batch)
  service.py               file follower, checkpointing, health/metrics HTTP
  features.py model.py     feature extraction, pure-Python forest inference
  anomaly.py               rules, port-scan aggregation, z-scores
  classification.py correlation.py scoring.py alerts.py
  tools.py                 tool interface (inference, intel, alerts, responses) with audit log
  zeek.py                  Zeek conn.log parser (TSV and JSON)
  store.py reports.py utils.py config.py
scripts/                   dataset conversion, training, evaluation
data/models/               trained models, metrics, benign baselines
infra/                     capture, Zeek, NetFlow, streaming, storage, systemd
tests/                     51 stdlib unittest tests (python -m unittest discover -s tests)
Dockerfile docker-compose.yml .github/workflows/ci.yml
```
