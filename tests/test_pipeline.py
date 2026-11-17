import json
import os
import tempfile
import unittest

from nids_agent.classification import classify_flow
from nids_agent.config import Config
from nids_agent.engine import NIDSAgent

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")
STUB = "autoencoder_anomaly"


def load_sample(label):
    with open(os.path.join(DATA, "sample_flows.jsonl"), encoding="utf-8") as f:
        return [dict(json.loads(line), label=label) for line in f if line.strip()]


class ClassificationTest(unittest.TestCase):
    def test_benign_model_does_not_mask_anomaly(self):
        r = classify_flow({}, None, True, {"label": "BENIGN", "confidence": 0.9}, Config())
        self.assertEqual((r["binary_label"], r["status"]), ("ATTACK", "SUSPECTED ANOMALY"))

    def test_attack_model_wins_over_anomaly(self):
        r = classify_flow({}, None, True, {"label": "DoS", "confidence": 0.9}, Config())
        self.assertEqual(r["binary_label"], "ATTACK")
        self.assertEqual(r["binary_confidence"], 0.9)

    def test_trained_model_benign_verdict_is_final(self):
        r = classify_flow({}, None, True, {"label": "BENIGN", "confidence": 0.9, "attack_score": 0.1}, Config())
        self.assertEqual(r["binary_label"], "BENIGN")

    def test_benign_model_no_anomaly_is_benign(self):
        r = classify_flow({}, None, False, {"label": "BENIGN", "confidence": 0.9}, Config())
        self.assertEqual(r["binary_label"], "BENIGN")


class PipelineTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        # Fixed-output stub model keeps these pipeline tests deterministic (the trained model has its own tests).
        self.agent = NIDSAgent(Config(logs_dir=self.tmp.name, data_dir=DATA, ml_model_name=STUB))

    def tearDown(self):
        self.tmp.cleanup()

    def metrics(self):
        with open(os.path.join(self.tmp.name, "metrics_state.json"), encoding="utf-8") as f:
            return json.load(f)

    def test_per_class_f1(self):
        # Rules flag flow-001 (DDoS). flow-003 is a single short flow, which is not a scan on its own
        # (port scans need many targets from one source), so it and flow-002 are predicted BENIGN.
        self.agent.process_batch(load_sample("ATTACK"))
        m = self.metrics()
        self.assertEqual(m["recall"], 0.3333)
        self.assertEqual(m["f1_per_class"], {"ATTACK": 0.5, "BENIGN": 0.0})

    def test_empty_baseline_hist_is_rebuilt(self):
        hist = os.path.join(self.tmp.name, "baseline_hist.json")
        open(hist, "w").close()
        self.agent.process_batch(load_sample("BENIGN"))
        with open(hist, encoding="utf-8") as f:
            self.assertIn("duration", json.load(f))
        self.assertEqual(self.metrics()["concept_drift"], 0.0)

    def read_jsonl(self, name):
        path = os.path.join(self.tmp.name, name)
        if not os.path.exists(path):
            return []
        with open(path, encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]

    def test_rerun_does_not_duplicate_events(self):
        self.agent.process_batch(load_sample("ATTACK"))
        first = self.read_jsonl("events.jsonl")
        self.agent.process_batch(load_sample("ATTACK"))
        self.assertEqual(len(self.read_jsonl("events.jsonl")), len(first))
        self.assertTrue(all(e.get("flow_id") for e in first))

    def test_response_not_executed_without_authorization(self):
        self.agent.process_batch(load_sample("ATTACK"))
        self.assertEqual(self.read_jsonl("responses.jsonl"), [])
        skipped = [d for d in self.read_jsonl("decision_log.jsonl") if d.get("stage") == "response"]
        self.assertTrue(skipped and all(d["status"] == "skipped" for d in skipped))

    def test_response_executed_when_authorized(self):
        agent = NIDSAgent(Config(logs_dir=self.tmp.name, data_dir=DATA, ml_model_name=STUB,
                                authorize_autonomous_response=True))
        alerts = agent.process_batch(load_sample("ATTACK"))
        responses = self.read_jsonl("responses.jsonl")
        # flow-001: DDoS rule, severity HIGH -> rate-limit the (public) source.
        self.assertEqual([(r["action"], r["target"]) for r in responses], [("rate-limit", "198.51.100.23")])
        self.assertIn("executed automatically", alerts[0])

    def test_related_events_list_is_capped(self):
        # Only the DDoS sample flow becomes an event, so 15 copies of the sample give 15 related events.
        flows = [dict(f, flow_id=f"{f['flow_id']}-{n}") for n in range(16) for f in load_sample("ATTACK")]
        self.agent.process_batch(flows[:45])
        alerts = self.agent.process_batch(flows[45:])
        related = next(l for l in alerts[0].split("\n") if "Related Events" in l)
        self.assertIn("15 related; latest:", related)
        self.assertEqual(related.count("NIDS-"), 10)

    def test_incident_report_lists_alerts(self):
        from nids_agent.reports import generate_incident_report
        self.agent.process_batch(load_sample("ATTACK"))
        report = generate_incident_report(self.tmp.name, ("2000-01-01T00:00:00Z", "2999-01-01T00:00:00Z"))
        self.assertIn("Incidents                 : 1", report)
        self.assertIn("CONFIRMED — DDoS → High-Rate", report)

    def test_rolling_rates_exclude_current_batch(self):
        self.agent.process_batch(load_sample("ATTACK"))
        self.assertNotIn("recall_7d_avg", self.metrics())
        self.agent.process_batch(load_sample("ATTACK"))
        self.assertEqual(self.metrics()["recall_7d_avg"], 0.3333)


def probe(i, src="198.51.100.9", dst="203.0.113.10", port=None, second=0):
    return {
        "flow_id": f"p{i}", "timestamp": f"2026-03-15T10:00:{second:02d}Z", "src_ip": src, "dst_ip": dst,
        "src_port": 40000 + i, "dst_port": port if port is not None else 1000 + i, "protocol": "TCP",
        "duration": 0.01, "bytes_sent": 60, "bytes_recv": 0, "packets_sent": 1, "packets_recv": 1,
        "flags": "SYN", "iat_mean": 0.0, "iat_std": 0.0,
    }


class PortScanTest(unittest.TestCase):
    def test_many_ports_one_host_is_vertical_scan(self):
        from nids_agent.anomaly import detect_port_scans
        hits = detect_port_scans([probe(i, second=i) for i in range(12)], Config(logs_dir=tempfile.mkdtemp()).rules)
        self.assertEqual(len(hits), 12)
        self.assertEqual({h["subtype"] for h in hits.values()}, {"Vertical"})

    def test_many_hosts_is_horizontal_scan(self):
        from nids_agent.anomaly import detect_port_scans
        flows = [probe(i, dst=f"203.0.113.{i}", port=22) for i in range(10)]
        hits = detect_port_scans(flows, Config(logs_dir=tempfile.mkdtemp()).rules)
        self.assertEqual({h["subtype"] for h in hits.values()}, {"Horizontal"})

    def test_few_targets_or_slow_probes_are_not_scans(self):
        from nids_agent.anomaly import detect_port_scans
        rules = Config(logs_dir=tempfile.mkdtemp()).rules
        self.assertEqual(detect_port_scans([probe(i) for i in range(5)], rules), {})
        # Same target repeated 12 times (e.g. DNS lookups) is not a scan.
        self.assertEqual(detect_port_scans([probe(i, port=53) for i in range(12)], rules), {})
        # 12 ports, but spread over > 60 s windows (5 s apart from minute to minute is fine; use hours).
        spread = [dict(probe(i), timestamp=f"2026-03-15T{10 + i:02d}:00:00Z") for i in range(12)]
        self.assertEqual(detect_port_scans(spread, rules), {})

    def test_large_scan_is_linear_time(self):
        import time
        from nids_agent.anomaly import detect_port_scans
        rules = Config(logs_dir=tempfile.mkdtemp()).rules
        flows = [dict(probe(i), dst_port=i, timestamp=f"2026-03-15T10:00:{i * 50 // 20000:02d}Z") for i in range(20000)]
        t0 = time.time()
        hits = detect_port_scans(flows, rules)
        self.assertEqual(len(hits), 20000)
        self.assertLess(time.time() - t0, 2.0)  # the old quadratic version needed minutes

    def test_placeholder_source_or_missing_timestamp_is_not_aggregated(self):
        from nids_agent.anomaly import detect_port_scans
        rules = Config(logs_dir=tempfile.mkdtemp()).rules
        self.assertEqual(detect_port_scans([probe(i, src="0.0.0.0") for i in range(12)], rules), {})
        no_ts = [dict(probe(i), timestamp=None) for i in range(12)]
        self.assertEqual(detect_port_scans(no_ts, rules), {})


class RedactionTest(unittest.TestCase):
    def test_only_internal_ranges_are_private(self):
        from nids_agent.utils import is_private_ip
        for ip in ("10.1.2.3", "172.20.0.1", "192.168.1.1", "127.0.0.1", "fd00::1"):
            self.assertTrue(is_private_ip(ip), ip)
        for ip in ("8.8.8.8", "198.51.100.23", "203.0.113.10", "172.32.0.1", "not-an-ip"):
            self.assertFalse(is_private_ip(ip), ip)


class FixedBaselineTest(unittest.TestCase):
    def test_fixed_ranges_normalize_and_clamp(self):
        from nids_agent.anomaly import compute_baseline_profile
        from nids_agent.preprocessing import preprocess_batch
        config = Config(logs_dir=tempfile.mkdtemp())
        profile = compute_baseline_profile(load_sample("BENIGN"), config)
        self.assertEqual((profile["packets_sent"]["min"], profile["packets_sent"]["max"]), (3.0, 1800.0))
        processed, _ = preprocess_batch([probe(0), dict(probe(1), packets_sent=5000)], config, profile)
        self.assertEqual(processed[0]["packets_sent_norm"], 0.0)  # below min -> clamped
        self.assertEqual(processed[1]["packets_sent_norm"], 1.0)  # above max -> clamped


if __name__ == "__main__":
    unittest.main()
