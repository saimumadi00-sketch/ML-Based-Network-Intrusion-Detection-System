# ML-Based Network Intrusion Detection System (NIDS-Agent)

This project implements the requested multi-stage NIDS pipeline with strict alert formatting, chain-of-custody logging, and privacy-safe outputs.

## Quick Start

```bash
python app.py --input data/sample_flows.jsonl --format jsonl
```

The core pipeline uses only the Python standard library, so any Python 3.12+ works (for example `py -3.14 app.py ...` on Windows). The venvs are only needed for the ML/ingestion extras.

## What It Does

- Stage 1: Preprocessing
  - Normalizes numeric features to [0,1]
  - One-hot encodes categorical features
  - Imputes missing values
  - Reports class imbalance (if labels are present)

- Stage 2: Anomaly Detection
  - Threshold-based rules
  - Statistical deviation vs baseline
  - Unsupervised scoring (autoencoder stub)
  - Flags reconstruction error > 2-sigma

- Stage 3: Threat Classification
  - Binary: BENIGN vs ATTACK
  - Category + Sub-type
  - Confidence scores (escalates if < 0.65)

- Stage 4: Correlation
  - Links related events (last 24h in local event store)
  - MITRE ATT&CK mapping

- Stage 5: Severity Scoring
  - CVSS-inspired scoring

## Privacy and Safety

- Internal RFC-1918 IPs are redacted in alerts by default.
- No payload content is logged or displayed.
- Autonomous responses are disabled unless `--authorize` is passed.

## Files

- `app.py`: CLI entrypoint
- `nids_agent/engine.py`: core pipeline
- `nids_agent/tools.py`: tool interface (model inference, intel, alerts, responses + audit logging)
- `nids_agent/features.py`, `nids_agent/model.py`: model features and pure-Python forest inference
- `scripts/cicids2017.py`, `scripts/train_model.py`: dataset converter and training/evaluation
- `data/models/`: trained model, its metrics, and the benign baseline profile
- `logs/`: decision logs, alerts, tool calls
- `data/`: sample inputs and local intel stubs
- `datasets/`: downloaded datasets (gitignored)

## Configuration

Optional inputs:

- `--baseline path/to/baseline.json`
- `--asset-map path/to/asset_map.json`
- `--authorize` to allow `execute_response`

Baseline profile schema:

```json
{
  "duration": {"mean": 1.2, "std": 0.3},
  "bytes_sent": {"mean": 1500, "std": 500}
}
```

Asset map schema:

```json
{
  "203.0.113.10": {"asset_tag": "web-01", "criticality": "CRITICAL"}
}
```

## Reports

```bash
python app.py --report hourly_summary
python app.py --report daily_digest
```

## Notes

- The tool interface supports local stubs for `query_flow_database`, `lookup_threat_intel`, and `run_ml_inference`.
- Replace stub data in `data/` with real feeds to integrate with your environment.

## Infrastructure Setup (optional)

See the `infra/` directory for operational setup scripts:

- `infra/capture/README.md` for tshark/tcpdump capture
- `infra/zeek/README.md` for Zeek PCAP processing
- `infra/streaming/README.md` for Kafka or Redis streaming
- `infra/netflow/README.md` for NetFlow/IPFIX collection (nfdump)
- `infra/storage/README.md` for PCAP cold storage and feature storage

## Project Status (2026-11-17)

**Working**

- Full 5-stage pipeline runs end to end on `data/sample_flows.jsonl` and produces alerts, decision logs, and tool-call logs in `logs/`.
- `hourly_summary` and `daily_digest` reports run; latency and concept-drift (KL divergence vs. `logs/baseline_hist.json`) are reported.
- Unit tests: `python -m unittest discover -s tests -v` (47 tests, stdlib only).
- Port scans are detected per source: ≥10 distinct (dst IP, port) targets from short probe flows within 60 s. One host → `Vertical`, several hosts → `Horizontal`.
- `--authorize` now works. For confident HIGH/CRITICAL attacks the engine calls `execute_response` (`HIGH` → rate-limit, `CRITICAL` → block the source; see `Config.response_actions`). Escalated incidents and internal sources are never acted on. Every decision, including skips, is written to `decision_log.jsonl`, and executed actions go to `responses.jsonl`.
- `--report incident_report [--hours N]` lists incidents from `alerts.jsonl` by severity and attack type, with escalations and autonomous responses.
- `recall_7d_avg` / `fpr_7d_avg` are computed from `predictions.jsonl` (previous 7 days, excluding the current batch), so the hourly degradation alerts can now fire.
- `--fit-baseline OUT --input FLOWS` saves mean/std and fixed min/max ranges; `--baseline OUT` then uses them for both z-scores and normalization, so drift histograms are comparable across batches.
- `.venv` rebuilt on Python 3.14 (the core pipeline needs no packages).

**Fixed on 2026-11-17**

- Crash on every run: `engine.py` imported `json` only inside one branch. The first run left an empty `baseline_hist.json`, and every later run failed to parse it. A missing or corrupt baseline file is now rebuilt automatically.
- `f1_per_class` reported the ATTACK F1 for both classes. BENIGN F1 is now computed with BENIGN as the positive class.
- A BENIGN ML verdict hid statistical (z-score) anomalies, so anomaly detection never fired while the model stub was in place. Only an ATTACK verdict from the model now takes precedence over an anomaly.

**Fixed on 2026-11-17 (second pass)**

- Re-running the same input no longer duplicates events: events carry `flow_id`, and an already-recorded flow is neither logged again nor correlated with itself.
- IP redaction used `ipaddress.is_private`, which also covers documentation/reserved ranges (e.g. 198.51.100.0/24, 203.0.113.0/24), so it hid non-internal addresses. "Internal" now means RFC 1918, loopback, link-local and IPv6 ULA only.
- Report windows were `(now, now)`; hourly summary is now the last hour, incident report the last `--hours` (default 24).

**Default model: trained on Zeek output (2026-11-17)**

`data/models/flow_classifier.json.gz` (1.3 MB) is trained on what production sees: Zeek `conn.log` from the CIC-IDS2017 packet captures (Tuesday–Friday, 1.74M connections). Labels come from CIC's TrafficLabelling CSVs, matched by endpoints, protocol and time (99.2–99.5% of TCP/UDP connections matched per day).

Why not the CICFlowMeter-trained model below? It did not transfer to Zeek. CICFlowMeter counts Ethernet padding as payload, so a SYN→RST port-scan probe has 6 response bytes in the CSVs but 0 in Zeek. The CSV model learned that artifact and caught 3.5% of Friday's port scans on Zeek output (99.9% on CSV features).

Results on **held-out connections** (connection-level split; the full pipeline is scored on test connections only, with rules still seeing all traffic in time order):

| | Attacks caught | False alarms | Precision |
|---|---|---|---|
| Model only | 94.7% | 0.47% | 98.9% |
| Rules only (port-scan aggregation, DoS signatures) | 43.2% | 0.19% | 99.0% |
| **Full pipeline** | **94.9%** | **0.57%** | **98.7%** |

- **Caught well (≥95%):** port scan (100%), DDoS (99.9%), DoS Hulk/GoldenEye/slowloris, FTP and SSH brute force (≥99.8%). The infiltration victim's internal scan: 90.5%.
- **Not caught:** web attacks (XSS 3%, web brute force 9%), Bot (28%), DoS Slowhttptest (27%). Many of these connections have exactly the same flow statistics as benign ones, so no flow-level model can separate them; they need HTTP/DNS-level features.
- **Label correction:** on Thursday 14:19–15:45 the infiltration victim (192.168.10.8) port-scans the internal network, and CIC labels those flows BENIGN (a documented CICIDS2017 labeling issue). Training and the scores above relabel them (`eval_zeek.KNOWN_LABEL_ERRORS`). With CIC's labels as published, the pipeline's false-alarm rate reads 6.0%, nearly all of it this scan.
- Model on test connections whose feature vector never occurs in training: 97.7% caught, 0.49% false alarms.
- Files: `flow_classifier.metrics.json` (model), `flow_classifier.pipeline_eval.json` (pipeline, per class), `baseline.json` (benign Zeek training connections).

Reproduce (needs Zeek; about 1.5 hours of streaming for 4 days at ~10 MB/s; PCAPs are not stored):

```bash
for d in Tuesday-WorkingHours Wednesday-workingHours Thursday-WorkingHours Friday-WorkingHours; do
  scripts/zeek_cic_pcap.sh $d datasets/cicids2017/zeek; done
# GeneratedLabelledFlows.zip (same mirror, sha256 7bdbef28...a27a) -> "datasets/cicids2017/TrafficLabelling /"
.venv/bin/python scripts/train_zeek_model.py datasets/cicids2017/zeek "datasets/cicids2017/TrafficLabelling "
python3 scripts/eval_zeek.py datasets/cicids2017/zeek/Friday-WorkingHours.conn.log \
    "datasets/cicids2017/TrafficLabelling /Friday-*.csv" --only-uids datasets/cicids2017/zeek/test_uids.txt --fix-known-label-errors
```

Changes found while testing on real Zeek output:

- **Port-scan rule fires on ordinary traffic:** it counted hosts making ordinary DNS/NTP/Kerberos requests to many servers (119 false hits in 1,300 benign connections). A probe must now get no payload back and start with a SYN; mid-stream fragments Zeek sees without one (`OTH`) don't count. This cut benign rule hits by 60% with no loss in scan detection.
- **Scan detection was quadratic:** it recomputed the target set for every window position. During Friday's 159k-probe scan, one batch took minutes, so the NIDS would have stalled under attack. It is now a single pass (50k probes: 0.16 s).
- **ICMP isn't scored:** the model is not run on ICMP, which it was never trained on (it flagged IPv6 multicast housekeeping as attacks).

**CICFlowMeter model (2026-11-17)**

`data/models/flow_classifier_cicflowmeter.json.gz` is the earlier 30-tree random forest trained on CIC-IDS2017's CICFlowMeter CSVs. Use it only for CICFlowMeter input (`Config(ml_model_name="flow_classifier_cicflowmeter")`, `--baseline data/models/baseline_cicflowmeter.json`). Inference is plain Python (`nids_agent/model.py`), so the pipeline still needs no packages, and the artifact is gzipped JSON rather than pickle. On 2,000 test flows it matches scikit-learn to within 1e-6.

- **Features** (`nids_agent/features.py`, shared by training and inference): destination port, duration, packets and bytes in each direction, IAT mean/std, and derived rates/ratios. These exist in Zeek, NetFlow and CICFlowMeter output, so production does not depend on CICFlowMeter.
- **Method:** 2.83M flows, deduplicated to 2.38M. Stratified 70/15/15 train/validation/test split. The ATTACK threshold is chosen on validation for ≤0.5% false positives; test is used once.
- **Held-out test results (356,300 flows):**

  | | Recall | False-positive rate | Precision |
  |---|---|---|---|
  | With IAT fields | 99.63% | 0.43% | 98.07% |
  | Without IAT (Zeek conn.log) | 99.44% | 0.39% | 98.24% |
  | Reference: all 78 CICFlowMeter columns | 99.96% | 0.50% | 97.63% |

  Half the training rows are duplicated with IAT blanked out. Without that, a model trained only with IAT jumped to 7.2% false positives on IAT-less input.
- **Per class:** DoS, DDoS, port scan and FTP/SSH brute force all have ≥89% precision and ≥98% recall. Weak spots are Bot (P 0.57 / R 0.75) and web attacks (XSS recall 5%, web brute force 58%); flow statistics barely separate these. Infiltration, SQL injection and Heartbleed have only 1–5 test flows, so their numbers mean little.
- **Full pipeline** on a stratified 6,013-flow test sample (`datasets/cicids2017/test_sample.jsonl`): recall 92.8%, false-positive rate 0.67%, 0.46 ms/flow. Recall is lower than above because the sample over-represents the hard rare classes (300 per class).
- Full numbers: `data/models/flow_classifier_cicflowmeter.metrics.json`. Baseline: `data/models/baseline_cicflowmeter.json` (benign training flows; min/max = 0.5th/99.5th percentiles).

Retrain:

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-train.txt
# CIC-IDS2017 MachineLearningCSV.zip (official: unb.ca/cic/datasets, registration required;
# mirror used here: huggingface.co/datasets/bencorn/CICIDS2017, sha256 c3f26274...7928) -> datasets/cicids2017/
.venv/bin/python scripts/train_model.py datasets/cicids2017/MachineLearningCVE [--compare-full] \
    --out data/models/flow_classifier_cicflowmeter.json.gz
```

Pipeline changes made while evaluating the model:

- The model gets the raw flow. Preprocessing filled missing fields with the baseline mean, so a missing IAT reached the model as a confident fake ~13 s value (pipeline false-positive rate 3.3% instead of 0.6%).
- A trained model's BENIGN verdict is final. The z-score check stays as alert evidence: on top of the model it added 1.6 points of false positives and no recall. The fixed-output stub still cannot mask an anomaly.
- The port-scan aggregation skips flows without a real source IP or a timestamp. On CIC data (all sources `0.0.0.0`) it had flagged 66% of benign flows as one giant scan.

**Zeek input and service mode (2026-11-17)**

- `--format zeek` reads Zeek `conn.log` (TSV or JSON) via `nids_agent/zeek.py`. Mapping: `uid`→`flow_id`, `ts`→`timestamp`, `id.*`→IPs/ports, `orig_/resp_bytes`→bytes, `orig_/resp_pkts`→packets, `history`→`flags`. conn.log has no inter-arrival times, so `iat_*` are empty, which the model was trained to handle.
- `--serve` runs continuously (`nids_agent/service.py`):

  ```bash
  python app.py --serve --follow /opt/zeek/logs/current/conn.log --format zeek \
      --baseline data/models/baseline.json --metrics-port 9108 [--print-alerts] [--authorize]
  ```

  - Follows the file like `tail -F`: survives Zeek's hourly rotation and truncation, and only reads complete lines. `--follow -` reads stdin.
  - Micro-batches of `--batch-size` flows (default 500), or whatever has arrived after `--max-wait` seconds (default 2).
  - Saves a checkpoint (inode + byte offset, `logs/checkpoint.json`) after each batch, so a restart resumes where it stopped. Delivery is at-least-once: a crash re-processes at most one batch.
  - A batch that raises goes to `logs/dead_letter.jsonl` and the service keeps running. `/healthz` returns 503 after 3 failed batches in a row.
  - `/healthz` (JSON) and `/metrics` (Prometheus) are served on 127.0.0.1 only. Metrics: flows, batches, errors, alerts by severity, last batch latency and age, source lag.
  - SIGTERM/SIGINT finishes the current batch, saves the checkpoint and exits with code 0.
  - Port-scan state carries across batches (`ScanContext`), so a scan split over several batches is still caught. Flows from earlier batches are not flagged retroactively.
- Measured: about 1,230 flows/s on one core, 64 MB RSS (30k CIC test flows via stdin, trained model).
- Fixed while load-testing:
  - The asset map was re-read from disk for every flow; it is now cached until the file changes.
  - Each alert listed every related incident ID, up to 1,000. It now shows the count plus the 10 most recent, which cut logs for 30k flows from 343 MB to 63 MB.

**Limits of these numbers.** CIC-IDS2017 is lab traffic from 2017 with known labeling errors, and a random split puts connections from the same attack sessions in train and test. All numbers above come from one network and one week. Expect lower accuracy on your own network. Run in detect-only mode on real traffic and measure there before trusting the figures.

**Still stubbed / incomplete**

- The old fixed-output stub (`data/autoencoder_anomaly.json`) is kept only for deterministic tests (`ml_model_name="autoencoder_anomaly"`).
- Threat intel (`data/threat_intel.json`) and flow DB (`data/flow_db.jsonl`) are small local samples, not real feeds.
- `data/sample_flows.jsonl` has no `label` field, so recall/FPR show `N/A` for it; use `datasets/cicids2017/test_sample.jsonl` for labeled runs.
- `execute_response` only records the action in `responses.jsonl`; it is not connected to a firewall or other enforcement point yet.
- A port scan produces one alert per probe flow; grouping them into a single incident would cut noise.
- Logs (`decision_log.jsonl`, `tool_calls.jsonl`, `alerts.jsonl`) have no rotation or retention; about 2 KB per flow in service mode. `load_recent_events` re-reads `events.jsonl` every batch.

**Known design limitations**

- Without `--baseline`, the anomaly baseline (mean/std) is computed from the batch being scored. In small batches, an attack inflates its own baseline, and with n flows no z-score can exceed √(n−1), so batches of 5 or fewer flows can never be flagged.
- Without `--baseline`, concept drift compares histograms of per-batch min-max-normalized values, which are not on the same scale. Fit a baseline with `--fit-baseline` to fix this.
- Single process, single core. Above ~1,000 flows/s, run several instances on disjoint sources, or move to step 3 storage plus a queue.

**Environment issues**

- `nids-env` (ML/ingestion extras, 251 packages) is still broken: it points to `C:\Users\saimu\AppData\Local\Programs\Python\Python312`, which no longer exists. Reinstall Python 3.12 and recreate it from `requirements.txt` (TensorFlow 2.21 may not support Python 3.14).
- Kafka and Docker are not installed (optional).

**Next steps**

1. Validate on a second dataset (UNSW-NB15, or CIC-IDS2018 for a different year) and on your own traffic in detect-only mode. Cross-dataset results are the honest estimate.
2. Cross-day check: train on Tuesday–Thursday, test on Friday's benign traffic, to see how the false-alarm rate holds on an unseen day. Then add Monday (benign only, 10.8 GB) for more benign variety.
3. For web attacks and bots, add application-layer features (Zeek `http.log`/`dns.log`); flow statistics alone cannot separate them.
4. Rebuild `nids-env`, install Npcap, and connect live capture (`scripts/start_capture.ps1` → Zeek → pipeline).
5. Connect `execute_response` to a real enforcement point (firewall API, Zeek/NetControl) and group per-flow scan alerts into one incident.
6. Production storage (step 3 of the roadmap): log rotation/retention, events and alerts in a database, an atomic incident counter. Then a Kafka/Redis source for the service.

**Potential**

The architecture is already in place: a staged pipeline, a tool interface with audit logging, chain-of-custody decision logs, privacy redaction, MITRE mapping, and drift monitoring. Replacing the stubs with a trained model and a real baseline turns it into a working NIDS that can be evaluated against published datasets. The capture and streaming infrastructure (tshark, Zeek, Redis/Kafka) is the path to live detection.

## Setup History

- Built the NIDS pipeline and CLI (`app.py`, `nids_agent/`).
- Installed Python 3.12 and created two venvs:
  - `.venv` for the minimal project runtime.
  - `nids-env` with ML/monitoring/ingestion deps; `requirements.txt` locked via `pip freeze`.
- Added infrastructure scripts/configs under `infra/` and helper scripts under `scripts/`.
- WSL Ubuntu installed; Zeek, tcpdump, nfdump, and redis-server installed inside WSL.
  - Redis and nfdump services are enabled and running in WSL.
  - Zeek is available at `/opt/zeek/bin/zeek` (symlinked to `/usr/local/bin/zeek`).
- Wireshark 4.4.14 installed on Windows; `tshark` available at `C:\Program Files\Wireshark\tshark.exe`.
- Npcap installer downloaded to `data/installers/npcap-1.87.exe` (needs interactive install for Windows capture).
- Kafka and Docker are not installed yet (optional; can be added if desired).
