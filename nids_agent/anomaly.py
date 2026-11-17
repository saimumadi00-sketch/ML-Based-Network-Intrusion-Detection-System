from __future__ import annotations

from datetime import datetime, timezone
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


def compute_baseline_profile(flows: List[Dict[str, Any]], config: Config) -> Dict[str, Dict[str, float]]:
    """Baseline with mean/std plus fixed min/max normalization ranges, for saving with --fit-baseline."""
    profile = compute_baseline(flows, config)
    for f in config.numeric_features:
        vals = [v for v in (safe_float(flow.get(f)) for flow in flows) if v is not None]
        profile[f]["min"] = min(vals) if vals else 0.0
        profile[f]["max"] = max(vals) if vals else 0.0
    return profile


def _parse_ts(value: Any) -> Optional[float]:
    if not value:
        return None
    try:
        text = str(value)
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except ValueError:
        return None


_UNSPECIFIED = {"0.0.0.0", "::", "UNKNOWN"}


def detect_port_scans(flows: List[Dict[str, Any]], rules: List[Dict[str, Any]]) -> Dict[int, Dict[str, Any]]:
    """Per-source aggregation for scan rules.

    A source is a scanner when, within `window_seconds`, its short probe flows (matching the rule's
    per-flow conditions) hit at least `min_distinct_targets` distinct (dst_ip, dst_port) pairs.
    Returns {flow index: rule (with subtype set to Vertical/Horizontal)} for every probe flow in such a window.
    """
    matches: Dict[int, Dict[str, Any]] = {}
    for rule in rules:
        agg = rule.get("aggregate")
        if not agg:
            continue
        window = float(agg.get("window_seconds", 60))
        min_targets = int(agg.get("min_distinct_targets", 10))

        by_src: Dict[str, List[Tuple[float, int]]] = {}
        for idx, flow in enumerate(flows):
            if idx in matches or not _matches_conditions(flow, rule.get("conditions", {})):
                continue
            src = flow.get("src_ip")
            ts = flow["_ts"] if "_ts" in flow else _parse_ts(flow.get("timestamp"))
            # A time-window rule needs a real source and a timestamp. Datasets without them (e.g.
            # CIC-IDS2017 CSVs use 0.0.0.0 placeholders) would otherwise look like one giant scanner.
            if not src or str(src) in _UNSPECIFIED or ts is None:
                continue
            by_src.setdefault(str(src), []).append((ts, idx))

        # Single pass per source with running counts of targets in the window: O(n log n). The previous
        # version rebuilt the target set for every window position, which was quadratic and took minutes per
        # batch during a large scan (Friday CIC-IDS2017: ~159k probes in 20 minutes).
        for probes in by_src.values():
            if len(probes) < min_targets:
                continue
            probes.sort()
            in_window: Dict[Tuple[Any, Any], int] = {}
            ips_in_window: Dict[Any, int] = {}
            start = 0
            marked = 0  # probes[:marked] already have a match for this source
            for end, (ts, idx) in enumerate(probes):
                target = (flows[idx].get("dst_ip"), flows[idx].get("dst_port"))
                in_window[target] = in_window.get(target, 0) + 1
                ips_in_window[target[0]] = ips_in_window.get(target[0], 0) + 1
                while ts - probes[start][0] > window:
                    old = (flows[probes[start][1]].get("dst_ip"), flows[probes[start][1]].get("dst_port"))
                    in_window[old] -= 1
                    if not in_window[old]:
                        del in_window[old]
                    ips_in_window[old[0]] -= 1
                    if not ips_in_window[old[0]]:
                        del ips_in_window[old[0]]
                    start += 1
                if len(in_window) < min_targets:
                    continue
                first = max(start, marked)
                if first > end:
                    continue
                hit = dict(rule)
                hit["subtype"] = "Vertical" if len(ips_in_window) == 1 else "Horizontal"
                hit["distinct_targets"] = len(in_window)
                for k in range(first, end + 1):
                    matches[probes[k][1]] = hit
                marked = end + 1
    return matches


class ScanContext:
    """Recent probe flows carried across batches, so a scan split over several batches is still detected.

    Only flows that could count toward an aggregate rule are kept (small dicts), pruned to the rule's
    time window behind the newest timestamp seen and capped at `max_flows`.
    """

    _KEEP = ("src_ip", "dst_ip", "dst_port", "timestamp", "packets_sent", "packets_recv", "bytes_recv", "duration")

    def __init__(self, rules: List[Dict[str, Any]], max_flows: int = 50_000) -> None:
        self.rules = rules
        self.agg_rules = [r for r in rules if r.get("aggregate")]
        self.window = max((float(r["aggregate"].get("window_seconds", 60)) for r in self.agg_rules), default=0.0)
        self.max_flows = max_flows
        self.flows: List[Dict[str, Any]] = []

    def detect(self, batch: List[Dict[str, Any]]) -> Dict[int, Dict[str, Any]]:
        if not self.agg_rules:
            return {}
        n_ctx = len(self.flows)
        hits = detect_port_scans(self.flows + batch, self.rules)
        result = {i - n_ctx: rule for i, rule in hits.items() if i >= n_ctx}

        kept = list(self.flows)
        for flow in batch:
            ts = _parse_ts(flow.get("timestamp"))
            src = flow.get("src_ip")
            if ts is None or not src or str(src) in _UNSPECIFIED:
                continue
            if any(_matches_conditions(flow, r.get("conditions", {})) for r in self.agg_rules):
                small = {k: flow.get(k) for k in self._KEEP}
                small["_ts"] = ts  # parsed once, reused by detect_port_scans on later batches
                kept.append(small)
        newest = max((f["_ts"] for f in kept), default=0.0)
        self.flows = [f for f in kept if f["_ts"] >= newest - self.window][-self.max_flows:]
        return result


def _matches_conditions(flow: Dict[str, Any], cond: Dict[str, Any]) -> bool:
    packets_sent = safe_float(flow.get("packets_sent")) or 0.0
    duration = safe_float(flow.get("duration")) or 0.0
    packets_min = cond.get("packets_sent_min")
    packets_max = cond.get("packets_sent_max")
    duration_max = cond.get("duration_max")
    bytes_recv_max = cond.get("bytes_recv_max")
    flags_require = cond.get("flags_require")
    # Only checked when the source reports flags (Zeek history); CSV datasets without flags are unaffected.
    if flags_require and flow.get("flags") and flags_require not in str(flow["flags"]).split(","):
        return False
    if bytes_recv_max is not None and (safe_float(flow.get("bytes_recv")) or 0.0) > bytes_recv_max:
        return False
    if packets_min is not None and packets_sent < packets_min:
        return False
    if packets_max is not None and packets_sent > packets_max:
        return False
    if duration_max is not None and duration > duration_max:
        return False
    return True


def apply_signature_rules(flow: Dict[str, Any], rules: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Per-flow rules only; aggregate rules are handled by detect_port_scans."""
    for rule in rules:
        if rule.get("aggregate"):
            continue
        if _matches_conditions(flow, rule.get("conditions", {})):
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
