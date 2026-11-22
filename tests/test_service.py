import json
import os
import shutil
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

from nids_agent.anomaly import ScanContext
from nids_agent.config import Config
from nids_agent.engine import NIDSAgent
from nids_agent.service import FollowFileSource, NIDSService

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE = os.path.join(ROOT, "tests", "fixtures", "conn.log")
DATA = os.path.join(ROOT, "data")

with open(FIXTURE, encoding="utf-8") as _f:
    _LINES = _f.read().splitlines(keepends=True)
HEADER = [l for l in _LINES if l.startswith("#fields") or l.startswith("#separator") or l.startswith("#types")]
ROWS = [l for l in _LINES if not l.startswith("#")]


def probe(i, second, src="198.51.100.9"):
    return {"flow_id": f"p{second}-{i}", "timestamp": f"2026-03-15T10:00:{second:02d}Z", "src_ip": src,
            "dst_ip": "203.0.113.10", "dst_port": 1000 + i, "packets_sent": 1, "duration": 0.01}


class FollowFileSourceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "conn.log")
        self.cp = os.path.join(self.tmp, "cp.json")

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def write(self, *parts, mode="a"):
        with open(self.path, mode, encoding="utf-8") as f:
            f.write("".join(parts))

    def test_reads_complete_lines_only_and_resumes_from_checkpoint(self):
        self.write(*HEADER, *ROWS[:3], ROWS[3][:20], mode="w")  # last line half-written
        src = FollowFileSource(self.path, "zeek", self.cp, from_start=True)
        self.assertEqual([f["flow_id"] for f in src.read(100)], ["CwebA1", "CdnsB2", "CnoC3"])
        self.write(ROWS[3][20:], ROWS[4])
        self.assertEqual([f["flow_id"] for f in src.read(100)], ["Cscan00", "Cscan01"])
        src.commit(); src.close()
        self.write(ROWS[5])
        # A new process resumes after the checkpoint and still knows the TSV header.
        resumed = FollowFileSource(self.path, "zeek", self.cp)
        self.assertEqual([f["flow_id"] for f in resumed.read(100)], ["Cscan02"])
        resumed.close()

    def test_without_checkpoint_starts_at_end_like_tail(self):
        self.write(*HEADER, *ROWS[:3], mode="w")
        src = FollowFileSource(self.path, "zeek", self.cp)
        self.assertEqual(src.read(100), [])
        self.write(ROWS[3])
        self.assertEqual([f["flow_id"] for f in src.read(100)], ["Cscan00"])
        src.close()

    @unittest.skipIf(os.name == "nt", "Windows cannot rename a file that is open; Zeek rotation is POSIX-only")
    def test_rotation_drains_old_file_then_reads_new(self):
        self.write(*HEADER, ROWS[0], mode="w")
        src = FollowFileSource(self.path, "zeek", self.cp, from_start=True)
        self.assertEqual(len(src.read(100)), 1)
        self.write(ROWS[1])
        os.rename(self.path, self.path + ".1")  # zeekctl-style rotation
        self.write(*HEADER, ROWS[2], mode="w")
        first = [f["flow_id"] for f in src.read(100)]
        second = [f["flow_id"] for f in src.read(100)]
        self.assertEqual(first + second, ["CdnsB2", "CnoC3"])
        src.close()

    def test_truncation_restarts_at_zero(self):
        self.write(*HEADER, *ROWS[:3], mode="w")
        src = FollowFileSource(self.path, "zeek", self.cp, from_start=True)
        src.read(100)
        self.write(*HEADER, ROWS[3], mode="w")
        src.read(100)  # notices the shrink
        self.assertEqual([f["flow_id"] for f in src.read(100)], ["Cscan00"])
        src.close()


class ScanContextTest(unittest.TestCase):
    def test_scan_split_across_batches_is_detected(self):
        ctx = ScanContext(Config(logs_dir=tempfile.mkdtemp()).rules)
        self.assertEqual(ctx.detect([probe(i, 1) for i in range(6)]), {})  # 6 targets: below 10
        hits = ctx.detect([probe(i, 2) for i in range(6, 12)])  # +6 within the window -> 12 targets
        self.assertEqual(sorted(hits), list(range(6)))

    def test_context_is_pruned_to_window(self):
        ctx = ScanContext(Config(logs_dir=tempfile.mkdtemp()).rules)
        ctx.detect([probe(i, 0) for i in range(6)])
        late = [dict(probe(i, 0), timestamp="2026-03-15T10:05:00Z") for i in range(6, 12)]
        self.assertEqual(ctx.detect(late), {})
        self.assertEqual(len(ctx.flows), 6)


class ServiceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "conn.log")
        with open(self.path, "w", encoding="utf-8") as f:
            f.write("".join(HEADER))

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def start(self, agent):
        src = FollowFileSource(self.path, "zeek", os.path.join(self.tmp, "cp.json"))
        svc = NIDSService(agent, src, batch_size=5, max_wait=0.2, poll_interval=0.02, metrics_port=0)
        t = threading.Thread(target=svc.run, daemon=True)
        t.start()
        return svc, t

    def append(self, rows):
        with open(self.path, "a", encoding="utf-8") as f:
            f.write("".join(rows))

    def wait_for(self, cond, timeout=5.0):
        end = time.time() + timeout
        while time.time() < end:
            if cond():
                return True
            time.sleep(0.02)
        return False

    def get(self, svc, path):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{svc.metrics_port}{path}", timeout=2) as r:
                return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    def test_follows_file_detects_scan_across_batches_and_serves_metrics(self):
        logs = os.path.join(self.tmp, "logs")
        agent = NIDSAgent(Config(logs_dir=logs, data_dir=DATA, ml_model_name="autoencoder_anomaly"))
        svc, t = self.start(agent)
        self.append(ROWS)  # 15 flows -> 3 batches of 5; the 12-port scan spans all of them
        self.assertTrue(self.wait_for(lambda: svc.stats.flows_total == 15))
        status, body = self.get(svc, "/metrics")
        self.assertEqual(status, 200)
        self.assertIn("nids_flows_total 15", body)
        status, body = self.get(svc, "/healthz")
        self.assertEqual((status, json.loads(body)["status"]), (200, "ok"))
        svc.stop(); t.join(5)
        with open(os.path.join(logs, "decision_log.jsonl"), encoding="utf-8") as f:
            rules = {d["flow_id"]: d["steps"][0]["rule"] for d in map(json.loads, f) if "steps" in d}
        # Batches: [3 normal + Cscan00-01], [Cscan02-06], [Cscan07-11]. Only the third batch crosses 10 distinct
        # targets (counting probes carried over from earlier batches); already-processed flows are not re-flagged.
        self.assertEqual({k for k, v in rules.items() if v == "possible_port_scan"},
                         {f"Cscan{i:02d}" for i in range(7, 12)})
        with open(os.path.join(self.tmp, "cp.json"), encoding="utf-8") as f:
            self.assertEqual(json.load(f)["offset"], os.path.getsize(self.path))

    def test_failing_batches_go_to_dead_letter_and_health_fails(self):
        class Broken(NIDSAgent):
            def process_batch(self, flows):
                raise RuntimeError("boom")

        logs = os.path.join(self.tmp, "logs")
        with self.assertLogs("nids.service", level="ERROR"):  # expected tracebacks, kept out of test output
            svc, t = self.start(Broken(Config(logs_dir=logs, data_dir=DATA)))
            self.append(ROWS)
            self.assertTrue(self.wait_for(lambda: svc.stats.batch_errors_total == 3))
        status, body = self.get(svc, "/healthz")
        self.assertEqual((status, json.loads(body)["status"]), (503, "failing"))
        svc.stop(); t.join(5)
        with open(os.path.join(logs, "dead_letter.jsonl"), encoding="utf-8") as f:
            parked = [json.loads(l) for l in f]
        self.assertEqual(len(parked), 15)
        self.assertIn("boom", parked[0]["error"])


if __name__ == "__main__":
    unittest.main()
