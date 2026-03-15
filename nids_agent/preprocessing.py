from __future__ import annotations

from typing import Any, Dict, List, Tuple

from .config import Config
from .utils import mean, safe_float


def _collect_numeric(flows: List[Dict[str, Any]], numeric_features: List[str]) -> Dict[str, List[float]]:
    values: Dict[str, List[float]] = {f: [] for f in numeric_features}
    for flow in flows:
        for f in numeric_features:
            val = safe_float(flow.get(f))
            if val is not None:
                values[f].append(val)
    return values


def preprocess_batch(flows: List[Dict[str, Any]], config: Config) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    numeric_values = _collect_numeric(flows, config.numeric_features)
    numeric_means = {f: mean(vals) for f, vals in numeric_values.items()}
    numeric_min = {f: min(vals) if vals else 0.0 for f, vals in numeric_values.items()}
    numeric_max = {f: max(vals) if vals else 0.0 for f, vals in numeric_values.items()}

    categorical_values = {f: set() for f in config.categorical_features}
    for flow in flows:
        for f in config.categorical_features:
            val = flow.get(f)
            if val is None:
                val = "UNKNOWN"
            categorical_values[f].add(str(val))

    missing_report: List[Dict[str, Any]] = []
    processed: List[Dict[str, Any]] = []

    for idx, flow in enumerate(flows):
        missing_fields = [f for f in config.required_flow_fields if flow.get(f) is None]
        if missing_fields:
            missing_report.append({"index": idx, "missing": missing_fields})

        out: Dict[str, Any] = dict(flow)

        # Impute and normalize numeric features
        for f in config.numeric_features:
            val = safe_float(flow.get(f))
            if val is None:
                val = numeric_means.get(f, 0.0)
                out[f"{f}_imputed"] = True
            else:
                out[f"{f}_imputed"] = False
            min_val = numeric_min.get(f, 0.0)
            max_val = numeric_max.get(f, 0.0)
            if max_val - min_val == 0:
                norm = 0.0
            else:
                norm = (val - min_val) / (max_val - min_val)
            out[f] = val
            out[f"{f}_norm"] = norm

        # One-hot encode categorical features
        for f in config.categorical_features:
            val = flow.get(f)
            if val is None:
                val = "UNKNOWN"
                out[f"{f}_imputed"] = True
            else:
                out[f"{f}_imputed"] = False
            for cat in sorted(categorical_values[f]):
                out[f"{f}_{cat}"] = 1 if str(val) == cat else 0

        processed.append(out)

    # Class imbalance reporting
    label_counts: Dict[str, int] = {}
    for flow in flows:
        label = flow.get("label") or flow.get("ground_truth")
        if label is None:
            continue
        label_counts[str(label)] = label_counts.get(str(label), 0) + 1

    class_imbalance = None
    if label_counts:
        total = sum(label_counts.values())
        ratios = {k: v / total for k, v in label_counts.items()}
        class_imbalance = {"counts": label_counts, "ratios": ratios}

    metadata = {
        "missing_report": missing_report,
        "numeric_means": numeric_means,
        "numeric_min": numeric_min,
        "numeric_max": numeric_max,
        "categorical_values": {k: sorted(list(v)) for k, v in categorical_values.items()},
        "class_imbalance": class_imbalance,
    }
    return processed, metadata
