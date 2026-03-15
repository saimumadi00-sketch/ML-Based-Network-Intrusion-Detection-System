from __future__ import annotations

import json
import os
from typing import Any, Dict

from .utils import redact_ip, utc_now_iso, write_json


def _next_incident_id(logs_dir: str) -> str:
    counter_path = os.path.join(logs_dir, "incident_counter.json")
    counter = {"date": None, "value": 0}
    if os.path.exists(counter_path):
        with open(counter_path, "r", encoding="utf-8") as f:
            try:
                counter = json.load(f)
            except json.JSONDecodeError:
                counter = {"date": None, "value": 0}
    today = utc_now_iso().split("T")[0]
    if counter.get("date") != today:
        counter = {"date": today, "value": 0}
    counter["value"] += 1
    write_json(counter_path, counter)
    return f"NIDS-{today}-{counter['value']:04d}"


def _format_attack_type(status: str, category: str, subtype: str) -> str:
    if status.startswith("INSUFFICIENT DATA"):
        return "INSUFFICIENT DATA — recommend manual review"
    if status in ("CONFIRMED ATTACK", "SUSPECTED ANOMALY"):
        prefix = "CONFIRMED" if status == "CONFIRMED ATTACK" else "SUSPECTED"
        return f"{prefix} — {category} → {subtype}"
    if status == "INFORMATIONAL":
        return f"INFO — {category} → {subtype}"
    return f"{status} — {category} → {subtype}"


def build_alert(
    logs_dir: str,
    redact_internal: bool,
    severity_label: str,
    confidence: float,
    threat_summary: Dict[str, Any],
    source: Dict[str, Any],
    target: Dict[str, Any],
    evidence: Dict[str, Any],
    recommended: Dict[str, Any],
    false_positive: Dict[str, Any],
) -> str:
    incident_id = _next_incident_id(logs_dir)
    timestamp = utc_now_iso()

    src_ip = redact_ip(str(source.get("ip", "UNKNOWN")), redact_internal)
    dst_ip = redact_ip(str(target.get("ip", "UNKNOWN")), redact_internal)

    alert = []
    alert.append("═══════════════════════════════════════════")
    alert.append(f"NIDS ALERT — [SEVERITY: {severity_label}]")
    alert.append("═══════════════════════════════════════════")
    alert.append(f"INCIDENT ID   : {incident_id}")
    alert.append(f"TIMESTAMP     : {timestamp}")
    alert.append(f"CONFIDENCE    : {confidence:.2f}")
    alert.append("")
    alert.append("THREAT SUMMARY")
    alert.append(f"  Attack Type   : {_format_attack_type(threat_summary['status'], threat_summary['category'], threat_summary['subtype'])}")
    alert.append(f"  MITRE ATT&CK  : {threat_summary['mitre_tactic']} → {threat_summary['mitre_technique']}")
    alert.append(f"  CVE Reference : {threat_summary.get('cve', 'N/A')}")
    alert.append("")
    alert.append("SOURCE")
    alert.append(f"  IP Address    : {src_ip}")
    alert.append(f"  Port          : {source.get('port', 'UNKNOWN')}")
    alert.append(f"  Geo/ASN       : {source.get('geo', 'UNKNOWN')}")
    alert.append(f"  Reputation    : {source.get('reputation', 'UNKNOWN')}")
    alert.append("")
    alert.append("TARGET")
    alert.append(f"  IP Address    : {dst_ip}")
    alert.append(f"  Port          : {target.get('port', 'UNKNOWN')}")
    asset_tag = target.get("asset_tag", "UNKNOWN")
    if redact_internal and asset_tag not in ("UNKNOWN", "N/A"):
        asset_tag = "REDACTED (INTERNAL)"
    alert.append(f"  Asset Tag     : {asset_tag}")
    alert.append(f"  Criticality   : {target.get('criticality', 'UNKNOWN')}")
    alert.append("")
    alert.append("EVIDENCE")
    alert.append(f"  Key Features  : {evidence.get('key_features', 'N/A')}")
    alert.append(f"  Baseline Δ    : {evidence.get('baseline_delta', 'N/A')}")
    alert.append(f"  Related Events: {evidence.get('related_events', 'NONE')}")
    alert.append("")
    alert.append("RECOMMENDED ACTIONS")
    alert.append(f"  Immediate     : {recommended.get('immediate', 'monitor')}")
    alert.append(f"  Short-term    : {recommended.get('short_term', 'review policies')}")
    alert.append(f"  Investigation : {recommended.get('investigation', 'review logs')}")
    alert.append("")
    alert.append(f"FALSE POSITIVE RISK: {false_positive.get('risk', 'MEDIUM')} — {false_positive.get('reason', 'insufficient data')}")
    alert.append("")
    return "\n".join(alert)
