from __future__ import annotations

import os
from typing import Any, Dict, List

from .utils import append_jsonl, utc_now_iso


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


def load_recent_events(logs_dir: str, max_items: int = 1000) -> List[Dict[str, Any]]:
    path = os.path.join(logs_dir, "events.jsonl")
    if not os.path.exists(path):
        return []
    events: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            try:
                events.append(__import__("json").loads(line))
            except Exception:
                continue
    return events[-max_items:]
