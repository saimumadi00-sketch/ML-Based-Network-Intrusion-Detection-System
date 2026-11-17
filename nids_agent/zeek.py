"""Zeek conn.log -> pipeline flow records.

Reads both Zeek log encodings: the default TSV (with "#fields" header) and JSON (LogAscii::use_json=T).
Field mapping (Zeek -> flow):
    uid -> flow_id, ts -> timestamp (ISO 8601 UTC), id.orig_h/id.orig_p -> src_ip/src_port,
    id.resp_h/id.resp_p -> dst_ip/dst_port, proto -> protocol, duration -> duration (s),
    orig_bytes/resp_bytes -> bytes_sent/bytes_recv (payload bytes),
    orig_pkts/resp_pkts -> packets_sent/packets_recv, history -> flags, service/conn_state kept as-is.
conn.log has no inter-arrival times, so iat_mean/iat_std are None; the model is trained to handle that.
Unset fields ("-") and empty fields become None.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Iterator, List, Optional

_UNSET = {"-", "(empty)", ""}

# Zeek history letters: uppercase = originator, lowercase = responder.
_HISTORY_FLAGS = {"s": "SYN", "h": "SYN-ACK", "a": "ACK", "d": "DATA", "f": "FIN", "r": "RST"}


def _num(value: Any) -> Optional[float]:
    if value is None or (isinstance(value, str) and value in _UNSET):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _int(value: Any) -> Optional[int]:
    v = _num(value)
    return int(v) if v is not None else None


def _str(value: Any) -> Optional[str]:
    if value is None or (isinstance(value, str) and value in _UNSET):
        return None
    return str(value)


def history_to_flags(history: Optional[str]) -> Optional[str]:
    if not history:
        return None
    seen: List[str] = []
    for ch in history:
        name = _HISTORY_FLAGS.get(ch.lower())
        if name and name not in seen:
            seen.append(name)
    return ",".join(seen) if seen else None


def record_to_flow(rec: Dict[str, Any]) -> Dict[str, Any]:
    ts = _num(rec.get("ts"))
    proto = _str(rec.get("proto"))
    return {
        "flow_id": _str(rec.get("uid")),
        "timestamp": (
            datetime.fromtimestamp(ts, tz=timezone.utc).isoformat().replace("+00:00", "Z") if ts is not None else None
        ),
        "src_ip": _str(rec.get("id.orig_h")),
        "src_port": _int(rec.get("id.orig_p")),
        "dst_ip": _str(rec.get("id.resp_h")),
        "dst_port": _int(rec.get("id.resp_p")),
        "protocol": proto.upper() if proto else None,
        "duration": _num(rec.get("duration")),
        "bytes_sent": _num(rec.get("orig_bytes")),
        "bytes_recv": _num(rec.get("resp_bytes")),
        "packets_sent": _num(rec.get("orig_pkts")),
        "packets_recv": _num(rec.get("resp_pkts")),
        "iat_mean": None,
        "iat_std": None,
        "flags": history_to_flags(_str(rec.get("history"))),
        "service": _str(rec.get("service")),
        "conn_state": _str(rec.get("conn_state")),
    }


class ConnLogParser:
    """Incremental parser: feed lines one at a time (works for files being appended to)."""

    def __init__(self) -> None:
        self.fields: Optional[List[str]] = None
        self.separator = "\t"

    def parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        line = line.rstrip("\n").rstrip("\r")
        if not line:
            return None
        if line.startswith("{"):
            try:
                return record_to_flow(json.loads(line))
            except json.JSONDecodeError:
                return None
        if line.startswith("#"):
            if line.startswith("#separator"):
                sep = line.split(" ", 1)[1].strip()
                self.separator = sep.encode().decode("unicode_escape") if sep.startswith("\\x") else sep
            elif line.startswith("#fields"):
                self.fields = line.split(self.separator)[1:]
            return None
        if self.fields is None:
            return None
        values = line.split(self.separator)
        if len(values) != len(self.fields):
            return None
        return record_to_flow(dict(zip(self.fields, values)))


def iter_conn_log(lines: Iterable[str]) -> Iterator[Dict[str, Any]]:
    parser = ConnLogParser()
    for line in lines:
        flow = parser.parse_line(line)
        if flow is not None:
            yield flow


def load_conn_log(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return list(iter_conn_log(f))
