# ML-Based Network Intrusion Detection System (NIDS-Agent)

This project implements the requested multi-stage NIDS pipeline with strict alert formatting, chain-of-custody logging, and privacy-safe outputs.

## Quick Start

```bash
python app.py --input data/sample_flows.jsonl --format jsonl
```

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
  - Flags reconstruction error > 2?

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
