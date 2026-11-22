from __future__ import annotations

import ipaddress
import json
import os
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple


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
    """Atomic: a crash mid-write leaves the old file, never a truncated one (checkpoint, incident counter)."""
    dir_path = os.path.dirname(path)
    if dir_path:
        os.makedirs(dir_path, exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)


# Size-based rotation for the JSONL logs (about 2 KB per flow in service mode, so unbounded files fill the disk).
# 0 disables rotation. Rotated files are <name>.1 (newest) ... <name>.N; reports read only the current file.
LOG_MAX_BYTES = int(os.environ.get("NIDS_LOG_MAX_BYTES", str(100 * 1024 * 1024)))
LOG_BACKUPS = int(os.environ.get("NIDS_LOG_BACKUPS", "5"))


def _rotate(path: str) -> None:
    for i in range(LOG_BACKUPS - 1, 0, -1):
        if os.path.exists(f"{path}.{i}"):
            os.replace(f"{path}.{i}", f"{path}.{i + 1}")
    if LOG_BACKUPS > 0:
        os.replace(path, f"{path}.1")
    else:
        os.remove(path)


_pending: Optional[Dict[str, List[str]]] = None  # path -> lines, while inside batched_appends()


@contextmanager
def batched_appends() -> Iterator[None]:
    """Buffer append_jsonl calls and write each file once on exit.

    One open/mkdir/close per record was ~65% of batch time. Not thread-safe: only the batch thread appends.
    """
    global _pending
    if _pending is not None:  # nested: the outer block flushes
        yield
        return
    _pending = {}
    try:
        yield
    finally:
        pending, _pending = _pending, None
        for path, lines in pending.items():
            _write_lines(path, lines)


def _write_lines(path: str, lines: List[str]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    data = "".join(lines)  # json.dumps output is ASCII, so len() is the byte count
    if LOG_MAX_BYTES > 0:
        try:
            if os.path.getsize(path) + len(data) > LOG_MAX_BYTES:
                _rotate(path)
        except FileNotFoundError:
            pass
    with open(path, "a", encoding="utf-8") as f:
        f.write(data)


def append_jsonl(path: str, record: Dict[str, Any]) -> None:
    line = json.dumps(record) + "\n"
    if _pending is not None:
        _pending.setdefault(path, []).append(line)
    else:
        _write_lines(path, [line])


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
