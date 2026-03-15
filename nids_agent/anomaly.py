from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from .config import Config
from .utils import safe_float


def compute_baseline(flows: List[Dict[str, Any]], config: Config) -> Dict[str, Dict[str, float]]:
    sums = {f: 0.0 for f in config.numeric_features}
    sums_sq = {f: 0.0 for f in config.numeric_features}
    counts = {f: 0 for f in config.numeric_features}
    for flow in flows:
        for f in config.numeric_features:
            val = safe_float(flow.get(f))
            if val is None:
                continue
            sums[f] += val
            sums_sq[f] += val * val
            counts[f] += 1
    baseline: Dict[str, Dict[str, float]] = {}
    for f in config.numeric_features:
        count = counts[f]
        if count == 0:
            mean = 0.0
            std = 1.0
        else:
            mean = sums[f] / count
            variance = max(0.0, (sums_sq[f] / count) - (mean * mean))
            std = variance ** 0.5 if variance > 0 else 1.0
        baseline[f] = {"mean": mean, "std": std}
    return baseline


def apply_signature_rules(flow: Dict[str, Any], rules: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    for rule in rules:
        cond = rule.get("conditions", {})
        packets_sent = safe_float(flow.get("packets_sent")) or 0.0
        duration = safe_float(flow.get("duration")) or 0.0
        packets_min = cond.get("packets_sent_min")
        packets_max = cond.get("packets_sent_max")
        duration_max = cond.get("duration_max")
        if packets_min is not None and packets_sent < packets_min:
            continue
        if packets_max is not None and packets_sent > packets_max:
            continue
        if duration_max is not None and duration > duration_max:
            continue
        return rule
    return None


def statistical_deviation(flow: Dict[str, Any], baseline: Dict[str, Dict[str, float]], config: Config) -> Dict[str, float]:
    z_scores: Dict[str, float] = {}
    for f in config.numeric_features:
        val = safe_float(flow.get(f))
        if val is None:
            continue
        mean = baseline.get(f, {}).get("mean", 0.0)
        std = baseline.get(f, {}).get("std", 1.0) or 1.0
        z_scores[f] = (val - mean) / std
    return z_scores


def anomaly_score(flow: Dict[str, Any], baseline: Dict[str, Dict[str, float]], config: Config) -> float:
    z_scores = statistical_deviation(flow, baseline, config)
    if not z_scores:
        return 0.0
    squared = [z * z for z in z_scores.values()]
    return (sum(squared) / len(squared)) ** 0.5


def is_anomalous(flow: Dict[str, Any], baseline: Dict[str, Dict[str, float]], config: Config) -> Tuple[bool, float, Dict[str, float]]:
    score = anomaly_score(flow, baseline, config)
    z_scores = statistical_deviation(flow, baseline, config)
    return score > config.anomaly_sigma_threshold, score, z_scores
