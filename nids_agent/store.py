from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .utils import append_jsonl, utc_now_iso


def _parse_iso(ts: str) -> Optional[datetime]:
    if not ts:
        return None
    try:
        if ts.endswith("Z"):
            ts = ts.replace("Z", "+00:00")
        return datetime.fromisoformat(ts)
    except ValueError:
        return None


def log_decision(logs_dir: str, record: Dict[str, Any]) -> None:
    path = os.path.join(logs_dir, "decision_log.jsonl")
    record = dict(record)
    record["timestamp"] = utc_now_iso()
    append_jsonl(path, record)


def log_event(logs_dir: str, event: Dict[str, Any]) -> None:
    path = os.path.join(logs_dir, "events.jsonl")
    event = dict(event)
    event["timestamp"] = utc_now_iso()
    append_jsonl(path, event)


def load_recent_events(
    logs_dir: str,
    since_ts: Optional[str] = None,
    max_items: int = 1000,
) -> List[Dict[str, Any]]:
    path = os.path.join(logs_dir, "events.jsonl")
    if not os.path.exists(path):
        return []
    events: List[Dict[str, Any]] = []
    since_dt = _parse_iso(since_ts) if since_ts else None
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            try:
                event = json.loads(line)
                if since_dt:
                    evt_dt = _parse_iso(event.get("timestamp"))
                    if evt_dt is None:
                        continue
                    if evt_dt < since_dt:
                        continue
                events.append(event)
            except Exception:
                continue
    return events[-max_items:]
