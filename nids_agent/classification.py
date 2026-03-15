from __future__ import annotations

from typing import Any, Dict, Optional

from .config import Config


def classify_flow(
    flow: Dict[str, Any],
    rule_match: Optional[Dict[str, Any]],
    anomaly_flag: bool,
    model_output: Optional[Dict[str, Any]],
    config: Config,
) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "binary_label": "BENIGN",
        "binary_confidence": 0.5,
        "category": "BENIGN",
        "category_confidence": 0.5,
        "subtype": "N/A",
        "subtype_confidence": 0.5,
        "status": "INFORMATIONAL",
        "escalate": False,
    }

    if rule_match is not None:
        result["binary_label"] = "ATTACK"
        result["binary_confidence"] = rule_match.get("confidence", 0.8)
        result["category"] = rule_match.get("category", "Other")
        result["category_confidence"] = rule_match.get("confidence", 0.8)
        result["subtype"] = rule_match.get("subtype", "N/A")
        result["subtype_confidence"] = rule_match.get("confidence", 0.8)
        result["status"] = "CONFIRMED ATTACK"
    elif model_output is not None:
        label = str(model_output.get("label", "BENIGN"))
        result["binary_label"] = "ATTACK" if label != "BENIGN" else "BENIGN"
        result["binary_confidence"] = float(model_output.get("confidence", 0.6))
        result["category"] = str(model_output.get("category", "Other" if label != "BENIGN" else "BENIGN"))
        result["category_confidence"] = float(model_output.get("confidence", 0.6))
        result["subtype"] = str(model_output.get("subtype", "N/A"))
        result["subtype_confidence"] = float(model_output.get("confidence", 0.6))
        result["status"] = "SUSPECTED ANOMALY" if label != "BENIGN" else "INFORMATIONAL"
    elif anomaly_flag:
        result["binary_label"] = "ATTACK"
        result["binary_confidence"] = 0.68
        result["category"] = "Other"
        result["category_confidence"] = 0.6
        result["subtype"] = "N/A"
        result["subtype_confidence"] = 0.55
        result["status"] = "SUSPECTED ANOMALY"
    else:
        result["status"] = "INFORMATIONAL"

    if (
        result["binary_confidence"] < config.low_confidence_threshold
        or result["category_confidence"] < config.low_confidence_threshold
        or result["subtype_confidence"] < config.low_confidence_threshold
    ):
        result["escalate"] = True

    return result
