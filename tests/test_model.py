import gzip
import json
import os
import sys
import tempfile
import unittest

from nids_agent.config import Config
from nids_agent.engine import NIDSAgent
from nids_agent.features import FEATURE_NAMES, MISSING, flow_features
from nids_agent.model import ForestModel

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
TRAINED = os.path.join(ROOT, "data", "models", "flow_classifier.json.gz")

CLASSES = ["BENIGN", "DDoS", "DoS Hulk"]
CLASS_MAP = {"BENIGN": ["BENIGN", "N/A"], "DDoS": ["DDoS", "LOIC"], "DoS Hulk": ["DoS", "Hulk"]}


def tiny_artifact(threshold=0.5):
    # One stump on packets_sent (feature 2): <= 100 -> mostly benign leaf, else attack leaf.
    tree = {
        "f": [2, 0, 0], "t": [100.0, -2.0, -2.0], "l": [1, -1, -1], "r": [2, -1, -1],
        "v": {"1": [[0, 0.9], [1, 0.1]], "2": [[0, 0.2], [1, 0.5], [2, 0.3]]},
    }
    return {"type": "random_forest", "version": "test", "feature_names": FEATURE_NAMES, "classes": CLASSES,
            "class_map": CLASS_MAP, "threshold": threshold, "trees": [tree]}


def flow(**kw):
    base = {"dst_port": 80, "duration": 1.0, "packets_sent": 10, "packets_recv": 5, "bytes_sent": 1000,
            "bytes_recv": 500, "iat_mean": 0.1, "iat_std": 0.01}
    base.update(kw)
    return base


class FeatureTest(unittest.TestCase):
    def test_features_and_missing(self):
        f = flow_features(flow())
        self.assertEqual(len(f), len(FEATURE_NAMES))
        named = dict(zip(FEATURE_NAMES, f))
        self.assertEqual(named["bytes_per_pkt_sent"], 100.0)
        self.assertEqual(named["packets_per_sec"], 15.0)
        missing = dict(zip(FEATURE_NAMES, flow_features(flow(iat_mean=None, bytes_recv="n/a"))))
        self.assertEqual((missing["iat_mean"], missing["bytes_recv"], missing["bytes_per_pkt_recv"]),
                         (MISSING, MISSING, MISSING))


class ForestModelTest(unittest.TestCase):
    def test_benign_below_threshold(self):
        out = ForestModel(tiny_artifact()).predict(flow(packets_sent=10))
        self.assertEqual((out["label"], out["category"]), ("BENIGN", "BENIGN"))
        self.assertAlmostEqual(out["confidence"], 0.9)

    def test_attack_reports_top_class_and_relative_confidences(self):
        out = ForestModel(tiny_artifact()).predict(flow(packets_sent=5000))
        self.assertEqual((out["label"], out["category"], out["subtype"]), ("DDoS", "DDoS", "LOIC"))
        self.assertAlmostEqual(out["confidence"], 0.8)
        self.assertAlmostEqual(out["subtype_confidence"], 0.625)  # 0.5 / 0.8 of the attack mass

    def test_threshold_controls_decision(self):
        self.assertEqual(ForestModel(tiny_artifact(threshold=0.95)).predict(flow(packets_sent=5000))["label"], "BENIGN")

    def test_rejects_other_feature_sets(self):
        bad = dict(tiny_artifact(), feature_names=["x"])
        with self.assertRaises(ValueError):
            ForestModel(bad)

    def test_engine_uses_forest_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "models"))
            with gzip.open(os.path.join(tmp, "models", "tiny.json.gz"), "wt", encoding="utf-8") as f:
                json.dump(tiny_artifact(), f)
            for name in ("threat_intel.json", "flow_db.jsonl"):
                with open(os.path.join(tmp, name), "w") as fh:
                    fh.write("{}" if name.endswith(".json") else "")
            agent = NIDSAgent(Config(logs_dir=os.path.join(tmp, "logs"), data_dir=tmp, ml_model_name="tiny"))
            alerts = agent.process_batch([dict(flow(packets_sent=300), flow_id="f1", src_ip="192.0.2.1",
                                               dst_ip="192.0.2.2", src_port=1, protocol="TCP")])
            self.assertIn("SUSPECTED — DDoS → LOIC", alerts[0])

    def test_engine_gives_model_raw_missing_values_not_imputed_ones(self):
        # Stump on iat_mean (feature 6): missing (-1) -> benign leaf; any real value -> attack leaf.
        art = tiny_artifact()
        art["trees"][0]["f"][0] = FEATURE_NAMES.index("iat_mean")
        art["trees"][0]["t"][0] = -0.5
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "models"))
            with gzip.open(os.path.join(tmp, "models", "tiny.json.gz"), "wt", encoding="utf-8") as f:
                json.dump(art, f)
            for name in ("threat_intel.json", "flow_db.jsonl"):
                with open(os.path.join(tmp, name), "w") as fh:
                    fh.write("{}" if name.endswith(".json") else "")
            agent = NIDSAgent(Config(logs_dir=os.path.join(tmp, "logs"), data_dir=tmp, ml_model_name="tiny"))
            base = dict(src_ip="192.0.2.1", dst_ip="192.0.2.2", src_port=1, protocol="TCP")
            # The second flow has an iat_mean, so preprocessing would impute a real-looking mean for the first.
            agent.process_batch([dict(flow(iat_mean=None), flow_id="a", **base), dict(flow(), flow_id="b", **base)])
            with open(os.path.join(tmp, "logs", "decision_log.jsonl"), encoding="utf-8") as f:
                steps = {d["flow_id"]: d["steps"] for d in map(json.loads, f) if "steps" in d}
            label = {fid: next(s for s in st if s["stage"] == "ml_inference")["label"] for fid, st in steps.items()}
            self.assertEqual(label, {"a": "BENIGN", "b": "DDoS"})


@unittest.skipUnless(os.path.exists(TRAINED), "trained model not present")
class TrainedModelTest(unittest.TestCase):
    def test_loads_and_predicts(self):
        model = ForestModel.load(TRAINED)
        self.assertIn("BENIGN", model.classes)
        out = model.predict(flow())
        self.assertIn(out["label"], model.classes)
        with open(TRAINED.replace(".json.gz", ".metrics.json"), encoding="utf-8") as f:
            self.assertLess(json.load(f)["parity_max_abs_diff"], 1e-4)  # pure Python == scikit-learn


class CicConverterTest(unittest.TestCase):
    def test_row_to_flow_units_and_labels(self):
        from cicids2017 import row_to_flow
        row = {" Destination Port": "80", " Flow Duration": "2500000", " Total Fwd Packets": "3",
               " Total Backward Packets": "2", "Total Length of Fwd Packets": "120",
               " Total Length of Bwd Packets": "0", " Flow IAT Mean": "1000", " Flow IAT Std": "Infinity",
               " Label": "Web Attack \x96 XSS"}
        f = row_to_flow(row, 7, "Thu")
        self.assertEqual((f["duration"], f["iat_mean"], f["iat_std"]), (2.5, 0.001, None))
        self.assertEqual((f["category"], f["subtype"], f["label"]), ("Web Attack", "XSS", "ATTACK"))


if __name__ == "__main__":
    unittest.main()
