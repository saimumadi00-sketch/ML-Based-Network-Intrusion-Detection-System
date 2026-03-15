from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


NUMERIC_FEATURES = [
    "duration",
    "bytes_sent",
    "bytes_recv",
    "packets_sent",
    "packets_recv",
    "iat_mean",
    "iat_std",
]

CATEGORICAL_FEATURES = [
    "protocol",
    "flags",
]

REQUIRED_FLOW_FIELDS = [
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
]

DEFAULT_RULES = [
    {
        "name": "possible_ddos",
        "category": "DDoS",
        "subtype": "High-Rate",
        "conditions": {
            "packets_sent_min": 1000,
            "duration_max": 2.0,
        },
        "confidence": 0.82,
        "impact": 8.0,
        "exploitability": 7.5,
    },
    {
        "name": "possible_dos",
        "category": "DoS",
        "subtype": "Hulk",
        "conditions": {
            "packets_sent_min": 400,
            "duration_max": 4.0,
        },
        "confidence": 0.75,
        "impact": 7.0,
        "exploitability": 6.5,
    },
    {
        "name": "possible_port_scan",
        "category": "Port Scan",
        "subtype": "Horizontal",
        "conditions": {
            "packets_sent_max": 5,
            "duration_max": 1.0,
        },
        "confidence": 0.70,
        "impact": 5.0,
        "exploitability": 6.0,
    },
]

MITRE_MAPPING = {
    "DDoS": ("Impact", "T1498: Network Denial of Service"),
    "DoS": ("Impact", "T1499: Endpoint Denial of Service"),
    "Port Scan": ("Reconnaissance", "T1046: Network Service Scanning"),
    "Brute Force": ("Credential Access", "T1110: Brute Force"),
    "Web Attack": ("Initial Access", "T1190: Exploit Public-Facing Application"),
    "Botnet": ("Command and Control", "T1071: Application Layer Protocol"),
    "Infiltration": ("Initial Access", "T1078: Valid Accounts"),
    "Other": ("Discovery", "T1082: System Information Discovery"),
}


@dataclass
class SeverityWeights:
    impact: float = 0.4
    exploitability: float = 0.3
    confidence: float = 0.2
    asset_criticality: float = 0.1


@dataclass
class Config:
    authorize_autonomous_response: bool = False
    numeric_features: List[str] = field(default_factory=lambda: list(NUMERIC_FEATURES))
    categorical_features: List[str] = field(default_factory=lambda: list(CATEGORICAL_FEATURES))
    required_flow_fields: List[str] = field(default_factory=lambda: list(REQUIRED_FLOW_FIELDS))
    rules: List[dict] = field(default_factory=lambda: list(DEFAULT_RULES))
    mitre_mapping: Dict[str, tuple] = field(default_factory=lambda: dict(MITRE_MAPPING))
    severity_weights: SeverityWeights = field(default_factory=SeverityWeights)
    anomaly_sigma_threshold: float = 2.0
    low_confidence_threshold: float = 0.65
    baseline_profile_path: Optional[str] = None
    asset_criticality_map_path: Optional[str] = None
    logs_dir: str = "logs"
    data_dir: str = "data"
    hourly_summary_interval_seconds: int = 3600
    redact_internal_ips: bool = True
