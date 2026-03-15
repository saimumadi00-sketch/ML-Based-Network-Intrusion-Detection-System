from __future__ import annotations

from typing import Any, Dict

from .config import Config
from .utils import clamp


CRITICALITY_MAP = {
    "CRITICAL": 9.0,
    "HIGH": 7.0,
    "STANDARD": 5.0,
    "UNKNOWN": 4.0,
}


def compute_severity(
    impact: float,
    exploitability: float,
    confidence: float,
    asset_criticality: str,
    config: Config,
) -> Dict[str, Any]:
    weights = config.severity_weights
    criticality_score = CRITICALITY_MAP.get(asset_criticality.upper(), 4.0)
    score = (
        (impact * weights.impact)
        + (exploitability * weights.exploitability)
        + ((confidence * 10.0) * weights.confidence)
        + (criticality_score * weights.asset_criticality)
    )
    score = clamp(score, 0.0, 10.0)

    if score >= 9.0:
        label = "CRITICAL"
    elif score >= 7.0:
        label = "HIGH"
    elif score >= 4.0:
        label = "MEDIUM"
    else:
        label = "LOW"

    return {"score": score, "label": label}
