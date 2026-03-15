from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .utils import append_jsonl, read_json, utc_now_iso


class ToolCallError(RuntimeError):
    pass


def _log_tool_call(log_path: str, tool: str, params: Dict[str, Any], status: str, error: Optional[str] = None) -> None:
    record = {
        "timestamp": utc_now_iso(),
        "tool": tool,
        "params": params,
        "status": status,
        "error": error,
    }
    append_jsonl(log_path, record)


class Toolset:
    def __init__(self, logs_dir: str, data_dir: str, authorize_autonomous_response: bool = False) -> None:
        self.logs_dir = logs_dir
        self.data_dir = data_dir
        self.authorize_autonomous_response = authorize_autonomous_response
        self.tool_log_path = os.path.join(self.logs_dir, "tool_calls.jsonl")

    def query_flow_database(self, filters: Dict[str, Any], time_range: Tuple[str, str]) -> List[Dict[str, Any]]:
        params = {"filters": filters, "time_range": time_range}
        try:
            db_path = os.path.join(self.data_dir, "flow_db.jsonl")
            if not os.path.exists(db_path):
                raise ToolCallError("flow_db.jsonl not found")
            start, end = time_range
            results: List[Dict[str, Any]] = []
            with open(db_path, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    ts = rec.get("timestamp")
                    if ts is None:
                        continue
                    if start <= ts <= end:
                        match = True
                        for k, v in filters.items():
                            if rec.get(k) != v:
                                match = False
                                break
                        if match:
                            results.append(rec)
            _log_tool_call(self.tool_log_path, "query_flow_database", params, "ok")
            return results
        except Exception as exc:
            _log_tool_call(self.tool_log_path, "query_flow_database", params, "error", str(exc))
            raise

    def lookup_threat_intel(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        params = {"indicator": indicator, "indicator_type": indicator_type}
        try:
            intel_path = os.path.join(self.data_dir, "threat_intel.json")
            if not os.path.exists(intel_path):
                raise ToolCallError("threat_intel.json not found")
            data = read_json(intel_path)
            result = data.get(indicator)
            if result is None:
                result = {"reputation": "CLEAN", "source": "local"}
            _log_tool_call(self.tool_log_path, "lookup_threat_intel", params, "ok")
            return result
        except Exception as exc:
            _log_tool_call(self.tool_log_path, "lookup_threat_intel", params, "error", str(exc))
            raise

    def run_ml_inference(self, feature_vector: Dict[str, Any], model_name: str) -> Dict[str, Any]:
        params = {"model_name": model_name}
        try:
            model_path = os.path.join(self.data_dir, f"{model_name}.json")
            if not os.path.exists(model_path):
                raise ToolCallError(f"model artifact not found: {model_name}")
            model_info = read_json(model_path)
            _log_tool_call(self.tool_log_path, "run_ml_inference", params, "ok")
            return {
                "model": model_name,
                "score": model_info.get("score", 0.0),
                "label": model_info.get("label", "BENIGN"),
                "confidence": model_info.get("confidence", 0.5),
            }
        except Exception as exc:
            _log_tool_call(self.tool_log_path, "run_ml_inference", params, "error", str(exc))
            raise

    def create_alert(self, alert_payload: str) -> None:
        params = {"bytes": len(alert_payload)}
        try:
            alert_path = os.path.join(self.logs_dir, "alerts.jsonl")
            append_jsonl(alert_path, {"timestamp": utc_now_iso(), "alert": alert_payload})
            _log_tool_call(self.tool_log_path, "create_alert", params, "ok")
        except Exception as exc:
            _log_tool_call(self.tool_log_path, "create_alert", params, "error", str(exc))
            raise

    def execute_response(self, action: str, target: str, justification: str) -> Dict[str, Any]:
        params = {"action": action, "target": target}
        try:
            if not self.authorize_autonomous_response:
                raise ToolCallError("AUTHORIZE_AUTONOMOUS_RESPONSE=false")
            record = {
                "timestamp": utc_now_iso(),
                "action": action,
                "target": target,
                "justification": justification,
            }
            response_path = os.path.join(self.logs_dir, "responses.jsonl")
            append_jsonl(response_path, record)
            _log_tool_call(self.tool_log_path, "execute_response", params, "ok")
            return {"status": "executed", "record": record}
        except Exception as exc:
            _log_tool_call(self.tool_log_path, "execute_response", params, "error", str(exc))
            raise

    def generate_report(self, report_type: str, time_range: Tuple[str, str]) -> str:
        params = {"report_type": report_type, "time_range": time_range}
        try:
            report_path = os.path.join(self.logs_dir, "reports", f"{report_type}.txt")
            if not os.path.exists(report_path):
                raise ToolCallError(f"report not found: {report_type}")
            with open(report_path, "r", encoding="utf-8") as f:
                content = f.read()
            _log_tool_call(self.tool_log_path, "generate_report", params, "ok")
            return content
        except Exception as exc:
            _log_tool_call(self.tool_log_path, "generate_report", params, "error", str(exc))
            raise
