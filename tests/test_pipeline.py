import json
import os
import tempfile
import unittest

from nids_agent.classification import classify_flow
from nids_agent.config import Config
from nids_agent.engine import NIDSAgent

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")


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

    def test_benign_model_no_anomaly_is_benign(self):
        r = classify_flow({}, None, False, {"label": "BENIGN", "confidence": 0.9}, Config())
        self.assertEqual(r["binary_label"], "BENIGN")


class PipelineTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.agent = NIDSAgent(Config(logs_dir=self.tmp.name, data_dir=DATA))

    def tearDown(self):
        self.tmp.cleanup()

    def metrics(self):
        with open(os.path.join(self.tmp.name, "metrics_state.json"), encoding="utf-8") as f:
            return json.load(f)

    def test_per_class_f1(self):
        # Rules flag flow-001 (DDoS) and flow-003 (port scan); flow-002 is predicted BENIGN.
        self.agent.process_batch(load_sample("ATTACK"))
        m = self.metrics()
        self.assertEqual(m["recall"], 0.6667)
        self.assertEqual(m["f1_per_class"], {"ATTACK": 0.8, "BENIGN": 0.0})

    def test_empty_baseline_hist_is_rebuilt(self):
        hist = os.path.join(self.tmp.name, "baseline_hist.json")
        open(hist, "w").close()
        self.agent.process_batch(load_sample("BENIGN"))
        with open(hist, encoding="utf-8") as f:
            self.assertIn("duration", json.load(f))
        self.assertEqual(self.metrics()["concept_drift"], 0.0)


if __name__ == "__main__":
    unittest.main()
