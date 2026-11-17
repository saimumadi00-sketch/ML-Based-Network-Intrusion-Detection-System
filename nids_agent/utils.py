from __future__ import annotations

import ipaddress
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


_INTERNAL_NETWORKS = [
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",  # RFC 1918
        "127.0.0.0/8", "169.254.0.0/16",                  # loopback, link-local
        "::1/128", "fc00::/7", "fe80::/10",               # IPv6 loopback, ULA, link-local
    )
]


def is_private_ip(ip_str: str) -> bool:
    """True for internal addresses (RFC 1918, loopback, link-local, IPv6 ULA).

    Deliberately narrower than ipaddress.is_private, which also counts documentation and
    reserved ranges (e.g. 198.51.100.0/24, 203.0.113.0/24) that are not internal hosts.
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(ip_obj in net for net in _INTERNAL_NETWORKS if net.version == ip_obj.version)


def redact_ip(ip_str: str, redact_internal: bool = True) -> str:
    if redact_internal and is_private_ip(ip_str):
        return "REDACTED (INTERNAL)"
    return ip_str


def safe_float(value: Any) -> Optional[float]:
    try:
        if value is None:
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def mean(values: Iterable[float]) -> float:
    vals = list(values)
    if not vals:
        return 0.0
    return sum(vals) / float(len(vals))


def clamp(value: float, min_value: float, max_value: float) -> float:
    return max(min_value, min(max_value, value))


def read_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: str, data: Any) -> None:
    dir_path = os.path.dirname(path)
    if dir_path:
        os.makedirs(dir_path, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def append_jsonl(path: str, record: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


def rolling_window(items: List[Any], max_items: int) -> List[Any]:
    if len(items) <= max_items:
        return items
    return items[-max_items:]


def calc_f1(precision: float, recall: float) -> float:
    if precision + recall == 0:
        return 0.0
    return 2 * (precision * recall) / (precision + recall)


def compute_confusion_matrix(y_true: List[str], y_pred: List[str], labels: List[str]) -> Dict[str, Dict[str, int]]:
    matrix: Dict[str, Dict[str, int]] = {label: {l: 0 for l in labels} for label in labels}
    for t, p in zip(y_true, y_pred):
        if t not in matrix:
            continue
        if p not in matrix[t]:
            continue
        matrix[t][p] += 1
    return matrix


def flatten_features(prefix: str, features: Dict[str, Any]) -> List[str]:
    return [f"{prefix}:{k}={v}" for k, v in features.items()]
