from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from nids_agent.config import Config
from nids_agent.engine import NIDSAgent
from nids_agent.reports import generate_daily_digest, generate_hourly_summary, generate_incident_report
from nids_agent.anomaly import compute_baseline_profile
from nids_agent.utils import utc_now_iso, write_json
from nids_agent.zeek import load_conn_log

DEFAULT_BASELINE = os.path.join("data", "models", "baseline.json")


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


def run_service(args: argparse.Namespace, config: Config) -> None:
    import logging

    from nids_agent.service import FollowFileSource, NIDSService, StdinSource

    if not args.follow:
        raise SystemExit("--serve needs --follow PATH (or - for stdin)")
    if args.format == "csv":
        raise SystemExit("--serve supports --format jsonl or zeek")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    if args.follow == "-":
        source = StdinSource(args.format)
    else:
        checkpoint = args.checkpoint or os.path.join(config.logs_dir, "checkpoint.json")
        source = FollowFileSource(args.follow, args.format, checkpoint, from_start=args.from_start)
    service = NIDSService(NIDSAgent(config=config), source, batch_size=args.batch_size, max_wait=args.max_wait,
                          metrics_port=args.metrics_port, metrics_host=args.metrics_host,
                          print_alerts=args.print_alerts)
    service.install_signal_handlers()
    service.run()


def main() -> None:
    parser = argparse.ArgumentParser(description="NIDS-Agent ML-based NIDS pipeline")
    parser.add_argument("--input", help="Input file path (jsonl or csv)")
    parser.add_argument("--format", default="jsonl", choices=["jsonl", "csv", "zeek"],
                        help="Input format (zeek = Zeek conn.log, TSV or JSON)")
    parser.add_argument("--baseline", help=f"Baseline profile path (json; default {DEFAULT_BASELINE} with the "
                                           "default model, if present)")
    parser.add_argument("--logs-dir", default="logs", help="Directory for alerts, decision logs and state")
    parser.add_argument("--asset-map", help="Asset criticality map path (json)")
    parser.add_argument("--authorize", action="store_true", help="Authorize autonomous response actions")
    parser.add_argument("--report", choices=["hourly_summary", "incident_report", "daily_digest"], help="Generate report")
    parser.add_argument("--hours", type=float, default=24.0, help="Report window in hours (incident_report)")
    parser.add_argument(
        "--fit-baseline",
        metavar="OUT",
        help="Fit a baseline profile (mean/std and fixed normalization ranges) on --input (benign/training "
             "flows) and save it to OUT; use it later with --baseline OUT",
    )
    serve = parser.add_argument_group("service mode")
    serve.add_argument("--serve", action="store_true", help="Run continuously, following --follow")
    serve.add_argument("--follow", metavar="PATH", help="File to follow (e.g. Zeek conn.log), or - for stdin")
    serve.add_argument("--from-start", action="store_true", help="Read the followed file from the beginning "
                       "(default: only new lines, unless a checkpoint exists)")
    serve.add_argument("--checkpoint", help="Checkpoint file (default: <logs>/checkpoint.json)")
    serve.add_argument("--batch-size", type=int, default=500)
    serve.add_argument("--max-wait", type=float, default=2.0, help="Flush a partial batch after N seconds")
    serve.add_argument("--metrics-port", type=int, help="Serve /healthz and /metrics on --metrics-host:PORT")
    serve.add_argument("--metrics-host", default="127.0.0.1",
                       help="Bind address for /healthz and /metrics (0.0.0.0 inside a container)")
    serve.add_argument("--print-alerts", action="store_true", help="Also print non-informational alerts")
    args = parser.parse_args()
    # Alerts contain box-drawing characters; a piped stdout on Windows (cp1252) crashed on the first print.
    sys.stdout.reconfigure(encoding="utf-8")

    config = Config(logs_dir=args.logs_dir)
    if args.baseline:
        config.baseline_profile_path = args.baseline
    elif config.ml_model_name == "flow_classifier" and os.path.exists(DEFAULT_BASELINE) and not args.fit_baseline:
        # Without a fixed baseline, z-scores are computed against the batch itself (weak on small batches).
        config.baseline_profile_path = DEFAULT_BASELINE
    if args.asset_map:
        config.asset_criticality_map_path = args.asset_map
    if args.authorize:
        config.authorize_autonomous_response = True

    if args.report:
        now_dt = datetime.now(timezone.utc)
        hours = 1.0 if args.report == "hourly_summary" else (args.hours if args.report == "incident_report" else 24.0)
        start = (now_dt - timedelta(hours=hours)).isoformat().replace("+00:00", "Z")
        time_range = (start, utc_now_iso())
        if args.report == "hourly_summary":
            print(generate_hourly_summary(config.logs_dir, time_range))
        elif args.report == "incident_report":
            print(generate_incident_report(config.logs_dir, time_range))
        else:
            print(generate_daily_digest(config.logs_dir, time_range))
        return

    if args.serve:
        run_service(args, config)
        return

    if not args.input:
        raise SystemExit("--input is required for batch processing")

    if args.format == "jsonl":
        flows = load_jsonl(args.input)
    elif args.format == "zeek":
        flows = load_conn_log(args.input)
    else:
        flows = load_csv(args.input)

    if args.fit_baseline:
        profile = compute_baseline_profile(flows, config)
        write_json(args.fit_baseline, profile)
        print(f"Baseline fitted on {len(flows)} flows -> {args.fit_baseline}")
        return

    agent = NIDSAgent(config=config)
    alerts = agent.process_batch(flows)
    for alert in alerts:
        print(alert)


if __name__ == "__main__":
    main()
