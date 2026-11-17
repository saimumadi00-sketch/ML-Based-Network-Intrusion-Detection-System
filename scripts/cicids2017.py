"""CIC-IDS2017 (MachineLearningCVE CSVs) -> pipeline flow records.

Usage as a converter:
    python scripts/cicids2017.py datasets/cicids2017/MachineLearningCVE out.jsonl [--limit N]

The CSVs have no IPs or timestamps, so converted flows carry placeholders for those fields.
Durations and inter-arrival times are converted from microseconds to seconds.
"""
from __future__ import annotations

import argparse
import csv
import glob
import json
import os
from typing import Dict, Iterator, Tuple

# CIC label -> (pipeline category, subtype). Categories match Config.MITRE_MAPPING keys.
LABEL_MAP: Dict[str, Tuple[str, str]] = {
    "BENIGN": ("BENIGN", "N/A"),
    "DDoS": ("DDoS", "LOIC"),
    "DoS Hulk": ("DoS", "Hulk"),
    "DoS GoldenEye": ("DoS", "GoldenEye"),
    "DoS slowloris": ("DoS", "Slowloris"),
    "DoS Slowhttptest": ("DoS", "Slowhttptest"),
    "PortScan": ("Port Scan", "Nmap"),
    "FTP-Patator": ("Brute Force", "FTP-Patator"),
    "SSH-Patator": ("Brute Force", "SSH-Patator"),
    "Bot": ("Botnet", "Ares"),
    "Web Attack Brute Force": ("Web Attack", "Brute Force"),
    "Web Attack XSS": ("Web Attack", "XSS"),
    "Web Attack Sql Injection": ("Web Attack", "SQL Injection"),
    "Infiltration": ("Infiltration", "N/A"),
    "Heartbleed": ("Other", "Heartbleed"),
}


def normalize_label(raw: str) -> str:
    # The web-attack labels contain a mangled en dash ("Web Attack \x96 XSS"); keep ASCII words only.
    words = "".join(ch if ch.isascii() and ch.isprintable() else " " for ch in raw).split()
    return " ".join(words)


def _f(row: Dict[str, str], key: str) -> float | None:
    try:
        val = float(row[key])
    except (KeyError, TypeError, ValueError):
        return None
    if val != val or val in (float("inf"), float("-inf")):
        return None
    return val


def row_to_flow(row: Dict[str, str], idx: int, source: str) -> Dict:
    row = {k.strip(): v for k, v in row.items() if k is not None}
    label = normalize_label(row.get("Label", ""))
    if label not in LABEL_MAP:
        raise ValueError(f"unknown CIC-IDS2017 label: {row.get('Label')!r}")
    category, subtype = LABEL_MAP[label]

    def us_to_s(key: str) -> float | None:
        v = _f(row, key)
        return None if v is None or v < 0 else v / 1e6

    port = _f(row, "Destination Port")
    return {
        "flow_id": f"{source}-{idx}",
        "src_ip": "0.0.0.0",
        "dst_ip": "0.0.0.0",
        "src_port": 0,
        "dst_port": int(port) if port is not None else None,
        "protocol": "UNKNOWN",
        "duration": us_to_s("Flow Duration"),
        "packets_sent": _f(row, "Total Fwd Packets"),
        "packets_recv": _f(row, "Total Backward Packets"),
        "bytes_sent": _f(row, "Total Length of Fwd Packets"),
        "bytes_recv": _f(row, "Total Length of Bwd Packets"),
        "iat_mean": us_to_s("Flow IAT Mean"),
        "iat_std": us_to_s("Flow IAT Std"),
        "label": "BENIGN" if category == "BENIGN" else "ATTACK",
        "cic_label": label,
        "category": category,
        "subtype": subtype,
    }


def iter_flows(csv_dir: str) -> Iterator[Dict]:
    paths = sorted(glob.glob(os.path.join(csv_dir, "*.csv")))
    if not paths:
        raise SystemExit(f"no CSV files in {csv_dir}")
    for path in paths:
        source = os.path.basename(path).split(".")[0]
        with open(path, "r", encoding="latin-1", newline="") as f:
            for idx, row in enumerate(csv.DictReader(f)):
                yield row_to_flow(row, idx, source)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csv_dir")
    ap.add_argument("out")
    ap.add_argument("--limit", type=int, default=0, help="stop after N flows (0 = all)")
    args = ap.parse_args()
    n = 0
    with open(args.out, "w", encoding="utf-8") as out:
        for flow in iter_flows(args.csv_dir):
            out.write(json.dumps(flow) + "\n")
            n += 1
            if args.limit and n >= args.limit:
                break
    print(f"wrote {n} flows -> {args.out}")


if __name__ == "__main__":
    main()
