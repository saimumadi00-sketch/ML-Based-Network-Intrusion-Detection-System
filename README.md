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
- `nids_agent/tools.py`: tool interface (local stubs + logging)
- `logs/`: decision logs, alerts, tool calls
- `data/`: sample inputs and local intel/model stubs

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
- Unit tests: `python -m unittest discover -s tests -v` (5 tests, stdlib only).
- `.venv` rebuilt on Python 3.14 (the core pipeline needs no packages).

**Fixed on 2026-11-17**

- Crash on every run: `engine.py` imported `json` only inside one branch. The first run left an empty `baseline_hist.json`, and every later run failed to parse it. A missing or corrupt baseline file is now rebuilt automatically.
- `f1_per_class` reported the ATTACK F1 for both classes. BENIGN F1 is now computed with BENIGN as the positive class.
- A BENIGN ML verdict hid statistical (z-score) anomalies, so anomaly detection never fired while the model stub was in place. Only an ATTACK verdict from the model now takes precedence over an anomaly.

**Still stubbed / incomplete**

- ML inference: `run_ml_inference` returns fixed output from `data/autoencoder_anomaly.json` (score 0.3, BENIGN, confidence 0.55); no trained model yet.
- Threat intel (`data/threat_intel.json`) and flow DB (`data/flow_db.jsonl`) are small local samples, not real feeds.
- Recall / FPR / F1 show `N/A` because the sample flows have no `label` field. Add labeled data (e.g. CIC-IDS2017) to get real metrics.
- `execute_response` exists, but the engine never calls it, so `--authorize` currently has no effect.
- `incident_report` is a placeholder; `recall_7d_avg` / `fpr_7d_avg` are never computed, so the degradation alerts in the hourly summary cannot fire.

**Known design limitations**

- The anomaly baseline (mean/std) is computed from the batch being scored unless `--baseline` is given. In small batches, an attack inflates its own baseline, and with n flows no z-score can exceed √(n−1), so batches of 5 or fewer flows can never be flagged.
- Concept drift compares histograms of per-batch min-max-normalized values, so batches are not on the same scale. Use fixed normalization ranges from training data instead.
- The port-scan rule matches any flow with ≤5 packets and ≤1 s duration (e.g. a single DNS lookup). It needs per-source aggregation (many distinct ports from one source) to be meaningful.
- Re-running the same input appends duplicate events, so correlation counts grow on each run.

**Environment issues**

- `nids-env` (ML/ingestion extras, 251 packages) is still broken: it points to `C:\Users\saimu\AppData\Local\Programs\Python\Python312`, which no longer exists. Reinstall Python 3.12 and recreate it from `requirements.txt` (TensorFlow 2.21 may not support Python 3.14).
- Kafka and Docker are not installed (optional).

**Next steps**

1. Get a labeled dataset (CIC-IDS2017 or UNSW-NB15) and convert it to the flow JSONL schema so the metrics become real.
2. Train a model (e.g. scikit-learn RandomForest or IsolationForest, both in `requirements.txt`), save it, and load it in `run_ml_inference` in place of the JSON stub.
3. Fit the baseline and normalization ranges on training data, save them, and pass them in with `--baseline` instead of computing them per batch.
4. Replace the port-scan rule with per-source aggregation over a time window.
5. Rebuild `nids-env`, install Npcap, and connect live capture (`scripts/start_capture.ps1` → Zeek → pipeline).
6. Wire `execute_response` into the engine behind `--authorize`, and finish `incident_report`.

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
