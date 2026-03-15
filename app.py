from __future__ import annotations

import argparse
import csv
import json
import os
from typing import Any, Dict, List

from nids_agent.config import Config
from nids_agent.engine import NIDSAgent
from nids_agent.reports import generate_daily_digest, generate_hourly_summary, generate_incident_report
from nids_agent.utils import utc_now_iso


def load_jsonl(path: str) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
    return records


def load_csv(path: str) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            records.append(dict(row))
    return records


def main() -> None:
    parser = argparse.ArgumentParser(description="NIDS-Agent ML-based NIDS pipeline")
    parser.add_argument("--input", help="Input file path (jsonl or csv)")
    parser.add_argument("--format", default="jsonl", choices=["jsonl", "csv"], help="Input format")
    parser.add_argument("--baseline", help="Baseline profile path (json)")
    parser.add_argument("--asset-map", help="Asset criticality map path (json)")
    parser.add_argument("--authorize", action="store_true", help="Authorize autonomous response actions")
    parser.add_argument("--report", choices=["hourly_summary", "incident_report", "daily_digest"], help="Generate report")
    args = parser.parse_args()

    config = Config()
    if args.baseline:
        config.baseline_profile_path = args.baseline
    if args.asset_map:
        config.asset_criticality_map_path = args.asset_map
    if args.authorize:
        config.authorize_autonomous_response = True

    if args.report:
        now = utc_now_iso()
        time_range = (now, now)
        if args.report == "hourly_summary":
            print(generate_hourly_summary(config.logs_dir, time_range))
        elif args.report == "incident_report":
            print(generate_incident_report(config.logs_dir, time_range))
        else:
            print(generate_daily_digest(config.logs_dir, time_range))
        return

    if not args.input:
        raise SystemExit("--input is required for batch processing")

    if args.format == "jsonl":
        flows = load_jsonl(args.input)
    else:
        flows = load_csv(args.input)

    agent = NIDSAgent(config=config)
    alerts = agent.process_batch(flows)
    for alert in alerts:
        print(alert)


if __name__ == "__main__":
    main()
