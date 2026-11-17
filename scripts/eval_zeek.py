"""Evaluate the pipeline's detectors on Zeek conn.log output of the CIC-IDS2017 PCAPs.

    python3 scripts/eval_zeek.py datasets/cicids2017/zeek/Friday-WorkingHours.conn.log \
        "datasets/cicids2017/TrafficLabelling /Friday-*.csv" [--out report.json]

Labels come from CIC's GeneratedLabelledFlows CSVs, matched to Zeek connections by the unordered
endpoint pair + protocol and time. CIC quirks handled here: local time (UTC-3), minute resolution,
12-hour clock without AM/PM (both readings are tried), and flows recorded in reverse direction.
A Zeek connection gets an attack label if any CIC flow matched to it is an attack (CICFlowMeter splits
long connections, so one Zeek connection can match several CIC flows). Unmatched connections are
reported and excluded.

Decisions are what the pipeline would do with the trained model: ATTACK if the model says so or a
signature/scan rule matches (rules use the same ScanContext as the service, batches of 500 in time order).
ICMP is excluded: the model skips it and CIC labels it inconsistently.
"""
from __future__ import annotations

import argparse
import csv
import glob
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "scripts"))

from cicids2017 import LABEL_MAP, normalize_label  # noqa: E402
from nids_agent.anomaly import ScanContext, _parse_ts, apply_signature_rules  # noqa: E402
from nids_agent.config import Config  # noqa: E402
from nids_agent.model import ForestModel  # noqa: E402
from nids_agent.zeek import load_conn_log  # noqa: E402

ADT = timezone(timedelta(hours=-3))
PROTO = {"6": "TCP", "17": "UDP"}
SLACK = 120.0  # seconds; CIC timestamps are truncated to the minute


def endpoint_key(proto, ip1, port1, ip2, port2):
    a, b = (str(ip1), int(port1)), (str(ip2), int(port2))
    return (proto,) + (a + b if a <= b else b + a)


def cic_start_candidates(text: str):
    """'7/7/2017 3:30' -> UTC epoch seconds for 03:30 and 15:30 local (ADT)."""
    date_part, time_part = text.strip().split(" ")
    d, m, y = (int(x) for x in date_part.split("/"))
    hh, mm = (int(x) for x in time_part.split(":")[:2])
    out = []
    for h in {hh, hh + 12} if hh < 12 else {hh}:
        if h < 24:
            out.append(datetime(y, m, d, h, mm, tzinfo=ADT).timestamp())
    return out


def load_cic_index(patterns):
    index = defaultdict(list)
    n = 0
    for pattern in patterns:
        for path in sorted(glob.glob(pattern)):
            with open(path, "r", encoding="latin-1", newline="") as f:
                reader = csv.reader(f)
                header = [h.strip() for h in next(reader)]
                col = {name: header.index(name) for name in
                       ("Source IP", "Source Port", "Destination IP", "Destination Port", "Protocol", "Timestamp", "Label")}
                for row in reader:
                    if len(row) < len(header):
                        continue
                    proto = PROTO.get(row[col["Protocol"]].strip())
                    if proto is None:
                        continue
                    label = normalize_label(row[col["Label"]])
                    if label not in LABEL_MAP:
                        continue
                    try:
                        key = endpoint_key(proto, row[col["Source IP"]], row[col["Source Port"]],
                                           row[col["Destination IP"]], row[col["Destination Port"]])
                        starts = cic_start_candidates(row[col["Timestamp"]])
                    except (ValueError, IndexError):
                        continue
                    index[key].append((starts, label))
                    n += 1
    return index, n


def label_flow(flow, index):
    try:
        key = endpoint_key(flow["protocol"], flow["src_ip"], flow["src_port"], flow["dst_ip"], flow["dst_port"])
    except (TypeError, ValueError):
        return None
    cands = index.get(key)
    if not cands:
        return None
    start = _parse_ts(flow["timestamp"])
    end = start + (flow.get("duration") or 0.0)
    labels = [lab for starts, lab in cands if any(start - SLACK <= s <= end + SLACK for s in starts)]
    if not labels:
        return None
    attacks = [lab for lab in labels if lab != "BENIGN"]
    return Counter(attacks).most_common(1)[0][0] if attacks else "BENIGN"


# Known CIC-IDS2017 labeling errors (corrected only with --fix-known-label-errors; both views are reported).
# Thursday 14:19-15:45 ADT: the infiltration victim 192.168.10.8 port-scans the internal network; CIC labels
# these flows BENIGN although its own scenario describes the scan (see Engelen et al., 2021, on CICIDS2017 labels).
KNOWN_LABEL_ERRORS = [
    {"src_ip": "192.168.10.8", "from": "2017-07-06T17:19", "to": "2017-07-06T18:46", "label": "Infiltration"},
]


def corrected_label(flow, label):
    if label == "BENIGN":
        for err in KNOWN_LABEL_ERRORS:
            if flow["src_ip"] == err["src_ip"] and err["from"] <= flow["timestamp"] <= err["to"]:
                return err["label"]
    return label


def rates(pairs):
    tp = sum(1 for t, p in pairs if t and p); fn = sum(1 for t, p in pairs if t and not p)
    fp = sum(1 for t, p in pairs if not t and p); tn = sum(1 for t, p in pairs if not t and not p)
    r = tp / max(tp + fn, 1); f = fp / max(fp + tn, 1); pr = tp / max(tp + fp, 1)
    return {"recall": round(r, 4), "fpr": round(f, 5), "precision": round(pr, 4),
            "tp": tp, "fp": fp, "fn": fn, "tn": tn}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("conn_log")
    ap.add_argument("cic_csv", nargs="+", help="glob(s) of TrafficLabelling CSVs for the same day")
    ap.add_argument("--model", default=os.path.join(ROOT, "data", "models", "flow_classifier.json.gz"))
    ap.add_argument("--out", help="write the report as JSON")
    ap.add_argument("--fix-known-label-errors", action="store_true",
                    help="relabel documented CIC labeling errors (KNOWN_LABEL_ERRORS) before scoring")
    ap.add_argument("--only-uids", help="score only these connection uids (one per line), e.g. the held-out "
                    "test split from train_zeek_model.py; rules still see all traffic in time order")
    args = ap.parse_args()

    index, n_cic = load_cic_index(args.cic_csv)
    flows = [f for f in load_conn_log(args.conn_log) if f["protocol"] in ("TCP", "UDP") and f["timestamp"]]
    flows.sort(key=lambda f: f["timestamp"])
    model = ForestModel.load(args.model)
    config = Config(logs_dir=os.path.join(ROOT, "datasets", "eval-tmp"))
    scan_ctx = ScanContext(config.rules)
    only = None
    if args.only_uids:
        with open(args.only_uids, encoding="utf-8") as f:
            only = {line.strip() for line in f if line.strip()}

    per_class = defaultdict(lambda: Counter())
    pairs = {"model": [], "rules": [], "pipeline": []}
    unmatched = 0
    score_hist = defaultdict(list)
    for start in range(0, len(flows), 500):
        batch = flows[start:start + 500]
        scans = scan_ctx.detect(batch)
        for i, flow in enumerate(batch):
            if only is not None and flow["flow_id"] not in only:
                continue
            truth = label_flow(flow, index)
            if truth is not None and args.fix_known_label_errors:
                truth = corrected_label(flow, truth)
            if truth is None:
                unmatched += 1
                continue
            out = model.predict(flow)
            m_attack = out["label"] != "BENIGN"
            rule = apply_signature_rules(flow, config.rules) or scans.get(i)
            r_attack = rule is not None
            is_attack = truth != "BENIGN"
            pairs["model"].append((is_attack, m_attack))
            pairs["rules"].append((is_attack, r_attack))
            pairs["pipeline"].append((is_attack, m_attack or r_attack))
            c = per_class[truth]
            c["n"] += 1
            c["model"] += m_attack
            c["rules"] += r_attack
            c["pipeline"] += m_attack or r_attack
            if m_attack and is_attack:
                c["model_right_category"] += LABEL_MAP[out["label"]][0] == LABEL_MAP[truth][0]
            score_hist[truth].append(out["attack_score"])

    considered = len(flows) if only is None else sum(1 for f in flows if f["flow_id"] in only)
    matched = considered - unmatched
    report = {
        "conn_log": os.path.basename(args.conn_log),
        "zeek_tcp_udp_connections": considered,
        "labels": "corrected (KNOWN_LABEL_ERRORS)" if args.fix_known_label_errors else "as published by CIC",
        "scored_subset": "only uids from " + os.path.basename(args.only_uids) if only is not None else "all",
        "matched_to_cic_labels": matched,
        "match_rate": round(matched / max(considered, 1), 4),
        "cic_flows_indexed": n_cic,
        "binary": {k: rates(v) for k, v in pairs.items()},
        "per_class_detection_rate": {
            k: {"n": v["n"], "model": round(v["model"] / v["n"], 4), "rules": round(v["rules"] / v["n"], 4),
                "pipeline": round(v["pipeline"] / v["n"], 4),
                **({"model_right_category": round(v["model_right_category"] / max(v["model"], 1), 4)}
                   if k != "BENIGN" else {})}
            for k, v in sorted(per_class.items(), key=lambda kv: -kv[1]["n"])
        },
        "median_attack_score": {k: round(sorted(v)[len(v) // 2], 4) for k, v in score_hist.items()},
    }
    text = json.dumps(report, indent=2)
    print(text)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text)


if __name__ == "__main__":
    main()
