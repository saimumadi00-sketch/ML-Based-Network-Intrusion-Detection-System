from __future__ import annotations

from typing import Any, Dict, List

from .config import Config


def correlate(flow: Dict[str, Any], history: List[Dict[str, Any]], category: str, config: Config) -> Dict[str, Any]:
    related = []
    src_ip = flow.get("src_ip")
    dst_ip = flow.get("dst_ip")
    dst_port = flow.get("dst_port")
    flow_id = flow.get("flow_id")
    for event in history:
        # A re-processed flow must not correlate with its own earlier event.
        if flow_id and event.get("flow_id") == flow_id:
            continue
        if src_ip and event.get("src_ip") == src_ip:
            related.append(event)
        elif dst_ip and event.get("dst_ip") == dst_ip:
            related.append(event)
        elif dst_port and event.get("dst_port") == dst_port:
            related.append(event)

    mitre = config.mitre_mapping.get(category, ("Discovery", "T1082: System Information Discovery"))
    incident_chain_size = len(related)
    zero_day = category == "Other"

    return {
        "related_events": related,
        "related_event_ids": [e.get("incident_id") for e in related if e.get("incident_id")],
        "incident_chain_size": incident_chain_size,
        "mitre_tactic": mitre[0],
        "mitre_technique": mitre[1],
        "zero_day_candidate": zero_day,
    }
