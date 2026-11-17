from __future__ import annotations

import json
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from .alerts import build_alert
from .anomaly import ScanContext, apply_signature_rules, compute_baseline, is_anomalous
from .classification import classify_flow
from .config import Config
from .correlation import correlate
from .preprocessing import preprocess_batch
from .reports import append_predictions, kl_divergence, rolling_rates, update_confusion_matrix, update_metrics_state
from .scoring import compute_severity
from .store import load_recent_events, log_decision, log_event
from .tools import Toolset
from .utils import calc_f1, is_private_ip


class NIDSAgent:
    def __init__(self, config: Optional[Config] = None) -> None:
        self.config = config or Config()
        self.tools = Toolset(
            logs_dir=self.config.logs_dir,
            data_dir=self.config.data_dir,
            authorize_autonomous_response=self.config.authorize_autonomous_response,
        )
        # Persists across process_batch calls, so a long-running service sees scans that span batches.
        self.scan_context = ScanContext(self.config.rules)
        self._asset_map_cache: Optional[tuple] = None

    def _asset_map(self) -> Dict[str, Any]:
        """Asset criticality map, re-read only when the file changes (was re-read for every flow)."""
        path = self.config.asset_criticality_map_path
        if not path or not os.path.exists(path):
            return {}
        mtime = os.path.getmtime(path)
        if self._asset_map_cache is None or self._asset_map_cache[0] != (path, mtime):
            with open(path, "r", encoding="utf-8") as f:
                self._asset_map_cache = ((path, mtime), json.load(f))
        return self._asset_map_cache[1]

    def _load_baseline_file(self) -> Optional[Dict[str, Dict[str, float]]]:
        if self.config.baseline_profile_path and os.path.exists(self.config.baseline_profile_path):
            with open(self.config.baseline_profile_path, "r", encoding="utf-8") as f:
                return json.load(f)
        return None

    def _maybe_respond(self, flow: Dict[str, Any], classification: Dict[str, Any], severity: Dict[str, Any],
                       recommended: Dict[str, str]) -> None:
        """Run execute_response for high-severity, confident ATTACKs when --authorize is set.

        Escalations stay with the SOC analyst, and internal (RFC-1918) sources are never acted on
        automatically. Every decision, including skips, goes to the decision log.
        """
        action = self.config.response_actions.get(severity["label"])
        if classification["binary_label"] != "ATTACK" or action is None:
            return
        target = str(flow.get("src_ip") or "")
        if not self.config.authorize_autonomous_response:
            reason = "not authorized (run with --authorize)"
        elif recommended["immediate"].startswith("ESCALATE"):
            reason = "escalated to SOC analyst"
        elif not target or is_private_ip(target):
            reason = "internal or missing source IP"
        else:
            reason = None
        record: Dict[str, Any] = {"flow_id": flow.get("flow_id"), "stage": "response", "action": action}
        if reason:
            record.update({"status": "skipped", "reason": reason})
            log_decision(self.config.logs_dir, record)
            return
        justification = (
            f"{classification['category']} ({classification['status']}), severity {severity['label']} "
            f"{severity['score']:.1f}, confidence {classification['binary_confidence']:.2f}"
        )
        try:
            self.tools.execute_response(action, target, justification)
            recommended["immediate"] = f"{action} source (executed automatically)"
            record["status"] = "executed"
        except Exception as exc:
            record.update({"status": "error", "error": str(exc)})
        log_decision(self.config.logs_dir, record)

    def process_batch(self, flows: List[Dict[str, Any]]) -> List[str]:
        start_time = time.time()
        fixed_baseline = self._load_baseline_file()
        processed, metadata = preprocess_batch(flows, self.config, fixed_baseline)
        baseline = fixed_baseline or compute_baseline(processed, self.config)
        scan_matches = self.scan_context.detect(processed)
        asset_map = self._asset_map()

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

        # Flows already recorded as events (re-runs of the same input) are not logged again.
        seen_flow_ids = {e.get("flow_id") for e in history if e.get("flow_id")}

        for idx, flow in enumerate(processed):
            decision_steps: List[Dict[str, Any]] = []

            rule_match = apply_signature_rules(flow, self.config.rules) or scan_matches.get(idx)
            decision_steps.append({
                "stage": "anomaly_rules",
                "match": rule_match is not None,
                "rule": rule_match.get("name") if rule_match else None,
            })

            anomalous, score, z_scores = is_anomalous(flow, baseline, self.config)
            decision_steps.append({"stage": "anomaly_model", "score": score, "anomalous": anomalous})

            model_output = None
            tool_failures: List[str] = []
            model_name = self.config.ml_model_name
            if str(flow.get("protocol") or "").upper() in self.config.ml_skip_protocols:
                decision_steps.append({"stage": "ml_inference", "model": model_name, "status": "skipped",
                                       "reason": f"protocol {flow.get('protocol')} outside model's training data"})
            else:
                try:
                    # The model gets the raw flow: it handles missing fields itself, while preprocessing's mean
                    # imputation would feed it plausible-looking but invented values.
                    model_output = self.tools.run_ml_inference(flows[idx], model_name)
                    decision_steps.append({
                        "stage": "ml_inference", "model": model_name, "status": "ok",
                        "version": model_output.get("model_version"), "label": model_output.get("label"),
                        "attack_score": model_output.get("attack_score"),
                    })
                except Exception as exc:
                    decision_steps.append({"stage": "ml_inference", "model": model_name, "status": "error",
                                           "error": str(exc)})
                    tool_failures.append(f"run_ml_inference:{model_name}")

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

            # Cap the list: a busy host can correlate with thousands of events, which made each alert
            # ~10 KB (319 MB of alerts for 30k flows). Keep the count plus the most recent IDs.
            related_ids = correlation["related_event_ids"]
            shown = related_ids[-10:]
            related_str = ", ".join(shown) if shown else "NONE"
            if len(related_ids) > len(shown):
                related_str = f"{len(related_ids)} related; latest: {related_str}"

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

            self._maybe_respond(flow, classification, severity, recommended)

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
            flow_id = flow.get("flow_id")
            if flow_id and flow_id in seen_flow_ids:
                continue
            if flow_id:
                seen_flow_ids.add(flow_id)
            log_event(self.config.logs_dir, {
                "flow_id": flow_id,
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

        # 7-day averages exclude this batch, so the hourly summary compares current vs. history.
        metrics_update.update(rolling_rates(self.config.logs_dir, days=7))

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
            # BENIGN F1 treats BENIGN as the positive class: precision = NPV, recall = specificity.
            npv = tn / (tn + fn) if (tn + fn) > 0 else 0.0
            specificity = tn / (tn + fp) if (tn + fp) > 0 else 0.0
            metrics_update.update({
                "recall": round(recall, 4),
                "fpr": round(fpr, 4),
                "f1_per_class": {
                    "ATTACK": round(calc_f1(precision, recall), 4),
                    "BENIGN": round(calc_f1(npv, specificity), 4),
                },
            })

        # Concept drift (KL divergence) on normalized numeric features
        hist_bins = 10
        current_hist: Dict[str, List[float]] = {}
        for feat in self.config.numeric_features:
            key = f"{feat}_norm"
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
            current_hist[feat] = [b / total for b in bins]

        hist_path = os.path.join(self.config.logs_dir, "baseline_hist.json")
        try:
            with open(hist_path, "r", encoding="utf-8") as fh:
                baseline_hist = json.load(fh)
        except (OSError, json.JSONDecodeError):
            # Missing or corrupt (e.g. left empty by an interrupted write): rebuild from this batch.
            baseline_hist = current_hist
            with open(hist_path, "w", encoding="utf-8") as fh:
                json.dump(baseline_hist, fh, indent=2)

        kl_scores = []
        for feat, p in current_hist.items():
            q = baseline_hist.get(feat, p)
            kl_scores.append(kl_divergence(p, q))
        metrics_update["concept_drift"] = round(max(kl_scores) if kl_scores else 0.0, 4)

        update_metrics_state(self.config.logs_dir, metrics_update)

        return alerts

