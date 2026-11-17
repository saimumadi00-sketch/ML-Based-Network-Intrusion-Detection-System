"""Model feature extraction shared by training (scripts/train_model.py) and inference (nids_agent/model.py).

Only fields of the pipeline's flow schema are used, so the same features can be computed from
CIC-IDS2017 CSVs, Zeek conn logs or NetFlow. Units: seconds and bytes (payload bytes, like Zeek's
orig_bytes/resp_bytes). Missing values are NaN-free: they become -1, which trees learn to route.
"""
from __future__ import annotations

from typing import Any, Dict, List

from .utils import safe_float

MISSING = -1.0

FEATURE_NAMES: List[str] = [
    "dst_port",
    "duration",
    "packets_sent",
    "packets_recv",
    "bytes_sent",
    "bytes_recv",
    "iat_mean",
    "iat_std",
    # derived
    "bytes_per_pkt_sent",
    "bytes_per_pkt_recv",
    "recv_send_byte_ratio",
    "packets_per_sec",
    "bytes_per_sec",
]


def _num(flow: Dict[str, Any], key: str) -> float:
    val = safe_float(flow.get(key))
    if val is None or val != val or val in (float("inf"), float("-inf")):
        return MISSING
    return max(val, 0.0)


def flow_features(flow: Dict[str, Any]) -> List[float]:
    port = _num(flow, "dst_port")
    duration = _num(flow, "duration")
    p_sent = _num(flow, "packets_sent")
    p_recv = _num(flow, "packets_recv")
    b_sent = _num(flow, "bytes_sent")
    b_recv = _num(flow, "bytes_recv")
    iat_mean = _num(flow, "iat_mean")
    iat_std = _num(flow, "iat_std")

    def ratio(a: float, b: float) -> float:
        if a == MISSING or b == MISSING:
            return MISSING
        return a / b if b > 0 else 0.0

    packets = p_sent + p_recv if MISSING not in (p_sent, p_recv) else MISSING
    total_bytes = b_sent + b_recv if MISSING not in (b_sent, b_recv) else MISSING
    # Rates use a 1 ms floor on duration so single-packet flows do not explode to infinity.
    dur_floor = max(duration, 0.001) if duration != MISSING else MISSING

    return [
        port,
        duration,
        p_sent,
        p_recv,
        b_sent,
        b_recv,
        iat_mean,
        iat_std,
        ratio(b_sent, p_sent),
        ratio(b_recv, p_recv),
        ratio(b_recv, b_sent + 1.0 if b_sent != MISSING else MISSING),
        ratio(packets, dur_floor),
        ratio(total_bytes, dur_floor),
    ]
