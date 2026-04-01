from __future__ import annotations

import math
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Tuple

from .utils import append_jsonl, read_json, utc_now_iso, write_json


def kl_divergence(p: List[float], q: List[float]) -> float:
    eps = 1e-9
    total = 0.0
    for pi, qi in zip(p, q):
        pi = max(pi, eps)
        qi = max(qi, eps)
        total += pi * math.log(pi / qi)
    return total


def update_confusion_matrix(logs_dir: str, y_true: List[str], y_pred: List[str]) -> Dict[str, Dict[str, int]]:
    path = os.path.join(logs_dir, "confusion_matrix.json")
    matrix: Dict[str, Dict[str, int]] = {}
    if os.path.exists(path):
        matrix = read_json(path)
    labels = sorted(list(set(y_true + y_pred)))
    for t, p in zip(y_true, y_pred):
        if t not in matrix:
            matrix[t] = {}
        if p not in matrix[t]:
            matrix[t][p] = 0
        matrix[t][p] += 1
    write_json(path, matrix)
    return matrix


def append_predictions(logs_dir: str, y_true: List[str], y_pred: List[str]) -> None:
    path = os.path.join(logs_dir, "predictions.jsonl")
    ts = utc_now_iso()
    for t, p in zip(y_true, y_pred):
        append_jsonl(path, {"timestamp": ts, "y_true": t, "y_pred": p})


def _parse_iso(ts: str) -> datetime | None:
    try:
        if ts.endswith("Z"):
            ts = ts.replace("Z", "+00:00")
        return datetime.fromisoformat(ts)
    except Exception:
        return None


def compute_metrics(logs_dir: str) -> Dict[str, Any]:
    path = os.path.join(logs_dir, "metrics_state.json")
    if not os.path.exists(path):
        return {}
    return read_json(path)


def write_metrics(logs_dir: str, metrics: Dict[str, Any]) -> None:
    path = os.path.join(logs_dir, "metrics_state.json")
    write_json(path, metrics)


def update_metrics_state(logs_dir: str, batch_metrics: Dict[str, Any]) -> None:
    state = compute_metrics(logs_dir)
    state.update(batch_metrics)
    write_metrics(logs_dir, state)


def generate_hourly_summary(logs_dir: str, time_range: Tuple[str, str]) -> str:
    state = compute_metrics(logs_dir)
    summary = []
    summary.append("HOURLY SUMMARY")
    summary.append(f"Time Range: {time_range[0]} to {time_range[1]}")
    summary.append(f"Detection Rate (Recall)   : {state.get('recall', 'N/A')}")
    summary.append(f"False Positive Rate       : {state.get('fpr', 'N/A')}")
    summary.append(f"F1 Score (per class)      : {state.get('f1_per_class', 'N/A')}")
    summary.append(f"Mean Inference Latency    : {state.get('mean_latency_ms', 'N/A')} ms")
    summary.append(f"Concept Drift Score       : {state.get('concept_drift', 'N/A')}")
    alerts = []
    try:
        drift = float(state.get("concept_drift", 0.0))
        if drift > 0.15:
            alerts.append("KL-divergence > 0.15 — recommend retraining")
    except (TypeError, ValueError):
        pass
    try:
        recall = float(state.get("recall", 0.0))
        recall_7d = float(state.get("recall_7d_avg", 0.0))
        if recall_7d > 0 and recall < recall_7d * 0.95:
            alerts.append("Recall drop > 5% vs 7-day avg — possible degradation")
    except (TypeError, ValueError):
        pass
    try:
        fpr = float(state.get("fpr", 0.0))
        fpr_7d = float(state.get("fpr_7d_avg", 0.0))
        if fpr_7d > 0 and fpr > fpr_7d * 2:
            alerts.append("FPR spike > 2x — investigate rule/feature changes")
    except (TypeError, ValueError):
        pass
    if alerts:
        summary.append(f"Drift Alerts              : {', '.join(alerts)}")
    else:
        summary.append("Drift Alerts              : NONE")
    summary.append("")
    return "\n".join(summary)


def generate_daily_digest(logs_dir: str, time_range: Tuple[str, str]) -> str:
    # Rolling 24h confusion matrix from predictions log
    matrix: Dict[str, Dict[str, int]] = {}
    pred_path = os.path.join(logs_dir, "predictions.jsonl")
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    if os.path.exists(pred_path):
        with open(pred_path, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    rec = __import__("json").loads(line)
                except Exception:
                    continue
                ts = _parse_iso(rec.get("timestamp", ""))
                if ts is None or ts < cutoff:
                    continue
                t = rec.get("y_true")
                p = rec.get("y_pred")
                if t is None or p is None:
                    continue
                if t not in matrix:
                    matrix[t] = {}
                if p not in matrix[t]:
                    matrix[t][p] = 0
                matrix[t][p] += 1
    summary = []
    summary.append("DAILY DIGEST")
    summary.append(f"Time Range: {time_range[0]} to {time_range[1]}")
    summary.append("Rolling 24h Confusion Matrix:")
    summary.append(str(matrix))
    summary.append("")
    return "\n".join(summary)


def generate_incident_report(logs_dir: str, time_range: Tuple[str, str]) -> str:
    summary = []
    summary.append("INCIDENT REPORT")
    summary.append(f"Time Range: {time_range[0]} to {time_range[1]}")
    summary.append("See alerts log for detailed incidents.")
    summary.append("")
    return "\n".join(summary)
