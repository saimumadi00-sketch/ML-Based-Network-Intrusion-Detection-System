from __future__ import annotations

import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from .alerts import build_alert
from .anomaly import apply_signature_rules, compute_baseline, is_anomalous
from .classification import classify_flow
from .config import Config
from .correlation import correlate
from .preprocessing import preprocess_batch
from .reports import append_predictions, kl_divergence, update_confusion_matrix, update_metrics_state
from .scoring import compute_severity
from .store import load_recent_events, log_decision, log_event
from .tools import Toolset


class NIDSAgent:
    def __init__(self, config: Optional[Config] = None) -> None:
        self.config = config or Config()
        self.tools = Toolset(
            logs_dir=self.config.logs_dir,
            data_dir=self.config.data_dir,
            authorize_autonomous_response=self.config.authorize_autonomous_response,
        )

    def _load_baseline(self, flows: List[Dict[str, Any]]) -> Dict[str, Dict[str, float]]:
        if self.config.baseline_profile_path and os.path.exists(self.config.baseline_profile_path):
            import json

            with open(self.config.baseline_profile_path, "r", encoding="utf-8") as f:
                return json.load(f)
        return compute_baseline(flows, self.config)

    def process_batch(self, flows: List[Dict[str, Any]]) -> List[str]:
        start_time = time.time()
        processed, metadata = preprocess_batch(flows, self.config)
        baseline = self._load_baseline(processed)

        if metadata.get("missing_report"):
            log_decision(self.config.logs_dir, {
                "stage": "preprocessing",
                "issue": "missing_fields",
                "details": metadata["missing_report"],
            })
        if metadata.get("class_imbalance"):
            log_decision(self.config.logs_dir, {
                "stage": "preprocessing",
                "issue": "class_imbalance",
                "details": metadata["class_imbalance"],
            })

        alerts: List[str] = []
        y_true: List[str] = []
        y_pred: List[str] = []
        info_bucket: List[Dict[str, Any]] = []
        end_ts = datetime.now(timezone.utc)
        start_ts = end_ts - timedelta(hours=24)
        history = load_recent_events(self.config.logs_dir, since_ts=start_ts.isoformat())
        try:
            db_events = self.tools.query_flow_database({}, (start_ts.isoformat(), end_ts.isoformat()))
            history.extend(db_events)
        except Exception as exc:
            log_decision(self.config.logs_dir, {
                "stage": "correlation",
                "issue": "query_flow_database_failed",
                "error": str(exc),
            })

        for flow in processed:
            decision_steps: List[Dict[str, Any]] = []

            rule_match = apply_signature_rules(flow, self.config.rules)
            decision_steps.append({"stage": "anomaly_rules", "match": rule_match is not None})

            anomalous, score, z_scores = is_anomalous(flow, baseline, self.config)
            decision_steps.append({"stage": "anomaly_model", "score": score, "anomalous": anomalous})

            model_output = None
            tool_failures: List[str] = []
            try:
                model_output = self.tools.run_ml_inference(flow, "autoencoder_anomaly")
                decision_steps.append({"stage": "ml_inference", "model": "autoencoder_anomaly", "status": "ok"})
            except Exception as exc:
                decision_steps.append({"stage": "ml_inference", "model": "autoencoder_anomaly", "status": "error", "error": str(exc)})
                tool_failures.append("run_ml_inference:autoencoder_anomaly")

            classification = classify_flow(flow, rule_match, anomalous, model_output, self.config)
            decision_steps.append({"stage": "classification", "result": classification})

            category = classification["category"] if classification["binary_label"] == "ATTACK" else "BENIGN"
            correlation = correlate(flow, history, category, self.config)
            decision_steps.append({"stage": "correlation", "result": {
                "related_event_count": correlation["incident_chain_size"],
                "zero_day_candidate": correlation["zero_day_candidate"],
            }})

            asset_criticality = "STANDARD"
            asset_tag = "UNKNOWN"
            if self.config.asset_criticality_map_path and os.path.exists(self.config.asset_criticality_map_path):
                import json

                with open(self.config.asset_criticality_map_path, "r", encoding="utf-8") as f:
                    asset_map = json.load(f)
                asset_info = asset_map.get(str(flow.get("dst_ip")), {})
                asset_criticality = asset_info.get("criticality", asset_criticality)
                asset_tag = asset_info.get("asset_tag", asset_tag)

            impact = 4.0
            exploitability = 4.0
            if rule_match is not None:
                impact = float(rule_match.get("impact", impact))
                exploitability = float(rule_match.get("exploitability", exploitability))
            severity = compute_severity(impact, exploitability, classification["binary_confidence"], asset_criticality, self.config)

            decision_steps.append({"stage": "severity", "score": severity})

            threat_intel = {"reputation": "UNKNOWN"}
            try:
                threat_intel = self.tools.lookup_threat_intel(str(flow.get("src_ip")), "ip")
            except Exception as exc:
                decision_steps.append({"stage": "threat_intel", "status": "error", "error": str(exc)})
                tool_failures.append("lookup_threat_intel:ip")

            data_quality_issue = len(metadata.get("missing_report", [])) > 0
            insufficient_data = (
                data_quality_issue
                and classification["binary_label"] == "BENIGN"
                and not anomalous
                and rule_match is None
            )

            if tool_failures and classification["binary_label"] == "BENIGN" and not anomalous and rule_match is None:
                insufficient_data = True

            if insufficient_data:
                classification["status"] = "INSUFFICIENT DATA — recommend manual review"

            log_decision(self.config.logs_dir, {
                "flow_id": flow.get("flow_id"),
                "steps": decision_steps,
            })

            label_true_raw = flow.get("label") or flow.get("ground_truth")
            if label_true_raw is not None:
                label_norm = "BENIGN" if str(label_true_raw).upper() == "BENIGN" else "ATTACK"
                y_true.append(label_norm)
                y_pred.append(classification["binary_label"])

            if classification["binary_label"] == "BENIGN" and classification["status"].startswith("INSUFFICIENT"):
                info_bucket.append(flow)
                continue

            if classification["binary_label"] == "BENIGN" and classification["status"] == "INFORMATIONAL":
                info_bucket.append(flow)
                continue

            threat_summary = {
                "status": classification["status"],
                "category": category,
                "subtype": classification["subtype"],
                "mitre_tactic": correlation["mitre_tactic"],
                "mitre_technique": correlation["mitre_technique"],
                "cve": flow.get("cve") or "N/A",
            }

            key_features = []
            for k, v in sorted(z_scores.items(), key=lambda x: abs(x[1]), reverse=True)[:5]:
                key_features.append(f"{k}={v:.2f}")
            key_features_str = "; ".join(key_features) if key_features else "N/A"
            imputed_fields = [k for k, v in flow.items() if k.endswith("_imputed") and v is True]
            imputed_note = f"; imputed_fields={','.join(imputed_fields)}" if imputed_fields else ""
            baseline_delta = (
                f"anomaly_score={score:.2f}; "
                f"conf_binary={classification['binary_confidence']:.2f}; "
                f"conf_category={classification['category_confidence']:.2f}; "
                f"conf_subtype={classification['subtype_confidence']:.2f}"
                f"{imputed_note}"
            )

            related_ids = correlation["related_event_ids"]
            related_str = ", ".join(related_ids) if related_ids else "NONE"

            recommended = {
                "immediate": "monitor",
                "short_term": "update detection rules",
                "investigation": "review NetFlow, IDS, and firewall logs",
            }

            false_positive = {
                "risk": "MEDIUM",
                "reason": "limited context",
            }

            if classification["binary_label"] == "ATTACK":
                recommended["immediate"] = "rate-limit"
                false_positive["risk"] = "LOW" if classification["binary_confidence"] >= 0.8 else "MEDIUM"
                false_positive["reason"] = "rule match" if rule_match else "anomaly score"

            if tool_failures:
                false_positive["risk"] = "HIGH"
                false_positive["reason"] = f"tool failure: {', '.join(tool_failures)}"
                recommended["investigation"] = f"manual review required; missing: {', '.join(tool_failures)}"

            if classification["escalate"] and classification["binary_label"] == "ATTACK":
                recommended["immediate"] = "ESCALATE TO SOC HUMAN ANALYST"

            if correlation["zero_day_candidate"]:
                recommended["investigation"] = "escalate for threat hunting and packet capture"

            if severity["label"] in ("HIGH", "CRITICAL") and classification["escalate"]:
                recommended["immediate"] = "ESCALATE TO SOC HUMAN ANALYST"

            if severity["label"] == "CRITICAL" and asset_criticality == "CRITICAL":
                recommended["immediate"] = "ESCALATE TO SOC HUMAN ANALYST"

            if correlation["incident_chain_size"] > 50:
                recommended["immediate"] = "ESCALATE TO SOC HUMAN ANALYST"

            if flow.get("authenticated_user") and flow.get("lateral_movement"):
                recommended["immediate"] = "ESCALATE TO SOC HUMAN ANALYST"

            alert = build_alert(
                logs_dir=self.config.logs_dir,
                redact_internal=self.config.redact_internal_ips,
                severity_label=severity["label"],
                confidence=classification["binary_confidence"],
                threat_summary=threat_summary,
                source={
                    "ip": flow.get("src_ip", "UNKNOWN"),
                    "port": flow.get("src_port", "UNKNOWN"),
                    "geo": threat_intel.get("geo", "UNKNOWN"),
                    "reputation": threat_intel.get("reputation", "UNKNOWN"),
                },
                target={
                    "ip": flow.get("dst_ip", "UNKNOWN"),
                    "port": flow.get("dst_port", "UNKNOWN"),
                    "asset_tag": asset_tag,
                    "criticality": asset_criticality,
                },
                evidence={
                    "key_features": key_features_str,
                    "baseline_delta": baseline_delta,
                    "related_events": related_str,
                },
                recommended=recommended,
                false_positive=false_positive,
            )

            self.tools.create_alert(alert)
            alerts.append(alert)

            incident_id = "UNKNOWN"
            for line in alert.split("\n"):
                if line.startswith("INCIDENT ID"):
                    incident_id = line.split(":", 1)[1].strip()
                    break
            log_event(self.config.logs_dir, {
                "incident_id": incident_id,
                "src_ip": flow.get("src_ip"),
                "dst_ip": flow.get("dst_ip"),
                "dst_port": flow.get("dst_port"),
                "category": category,
            })

        if info_bucket:
            info_alert = build_alert(
                logs_dir=self.config.logs_dir,
                redact_internal=self.config.redact_internal_ips,
                severity_label="LOW",
                confidence=0.5,
                threat_summary={
                    "status": "INFORMATIONAL",
                    "category": "BENIGN",
                    "subtype": "N/A",
                    "mitre_tactic": "N/A",
                    "mitre_technique": "N/A",
                    "cve": "N/A",
                },
                source={
                    "ip": "MULTIPLE",
                    "port": "MULTIPLE",
                    "geo": "UNKNOWN",
                    "reputation": "CLEAN",
                },
                target={
                    "ip": "MULTIPLE",
                    "port": "MULTIPLE",
                    "asset_tag": "UNKNOWN",
                    "criticality": "STANDARD",
                },
                evidence={
                    "key_features": f"informational_flows={len(info_bucket)}",
                    "baseline_delta": "N/A",
                    "related_events": "NONE",
                },
                recommended={
                    "immediate": "monitor",
                    "short_term": "review noise rules",
                    "investigation": "review sampling of benign flows",
                },
                false_positive={
                    "risk": "LOW",
                    "reason": "batched informational events",
                },
            )
            self.tools.create_alert(info_alert)
            alerts.append(info_alert)

        latency_ms = (time.time() - start_time) * 1000.0
        metrics_update: Dict[str, Any] = {"mean_latency_ms": round(latency_ms / max(len(flows), 1), 2)}

        if y_true and y_pred:
            update_confusion_matrix(self.config.logs_dir, y_true, y_pred)
            append_predictions(self.config.logs_dir, y_true, y_pred)
            tp = sum(1 for t, p in zip(y_true, y_pred) if t == "ATTACK" and p == "ATTACK")
            tn = sum(1 for t, p in zip(y_true, y_pred) if t == "BENIGN" and p == "BENIGN")
            fp = sum(1 for t, p in zip(y_true, y_pred) if t == "BENIGN" and p == "ATTACK")
            fn = sum(1 for t, p in zip(y_true, y_pred) if t == "ATTACK" and p == "BENIGN")
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
            metrics_update.update({
                "recall": round(recall, 4),
                "fpr": round(fpr, 4),
                "f1_per_class": {"ATTACK": round(f1, 4), "BENIGN": round(f1, 4)},
            })

        # Concept drift (KL divergence) on normalized numeric features
        hist_bins = 10
        current_hist: Dict[str, List[float]] = {}
        for f in self.config.numeric_features:
            key = f"{f}_norm"
            values = [flow.get(key, 0.0) for flow in processed]
            bins = [0] * hist_bins
            for v in values:
                try:
                    idx = int(float(v) * hist_bins)
                except (TypeError, ValueError):
                    idx = 0
                if idx >= hist_bins:
                    idx = hist_bins - 1
                if idx < 0:
                    idx = 0
                bins[idx] += 1
            total = sum(bins) or 1
            current_hist[f] = [b / total for b in bins]

        baseline_hist = {}
        hist_path = os.path.join(self.config.logs_dir, "baseline_hist.json")
        if os.path.exists(hist_path):
            import json

            with open(hist_path, "r", encoding="utf-8") as f:
                baseline_hist = json.load(f)
        else:
            baseline_hist = current_hist
            with open(hist_path, "w", encoding="utf-8") as f:
                json.dump(baseline_hist, f, indent=2)

        kl_scores = []
        for f, p in current_hist.items():
            q = baseline_hist.get(f, p)
            kl_scores.append(kl_divergence(p, q))
        metrics_update["concept_drift"] = round(max(kl_scores) if kl_scores else 0.0, 4)

        update_metrics_state(self.config.logs_dir, metrics_update)

        return alerts

