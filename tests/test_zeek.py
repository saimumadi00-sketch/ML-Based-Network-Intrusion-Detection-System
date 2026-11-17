import json
import os
import tempfile
import unittest

from nids_agent.anomaly import detect_port_scans
from nids_agent.config import Config
from nids_agent.zeek import ConnLogParser, history_to_flags, load_conn_log

FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "conn.log")
DATA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")


class ZeekConnLogTest(unittest.TestCase):
    def test_tsv_fields_map_to_flow_schema(self):
        flows = load_conn_log(FIXTURE)
        self.assertEqual(len(flows), 15)
        web = flows[0]
        self.assertEqual(web["flow_id"], "CwebA1")
        self.assertEqual(web["timestamp"], "2025-11-17T10:00:00.123456Z")
        self.assertEqual((web["src_ip"], web["src_port"], web["dst_ip"], web["dst_port"]),
                         ("192.168.1.20", 51544, "93.184.216.34", 443))
        self.assertEqual((web["protocol"], web["duration"], web["bytes_sent"], web["bytes_recv"]),
                         ("TCP", 2.413, 1830.0, 48211.0))
        self.assertEqual((web["packets_sent"], web["packets_recv"]), (42.0, 48.0))
        self.assertIsNone(web["iat_mean"])
        self.assertEqual(web["flags"], "SYN,SYN-ACK,ACK,DATA,FIN")

    def test_unset_fields_become_none(self):
        no_reply = load_conn_log(FIXTURE)[2]
        self.assertEqual((no_reply["duration"], no_reply["bytes_sent"], no_reply["service"]), (None, None, None))
        self.assertEqual(no_reply["conn_state"], "S0")

    def test_json_lines(self):
        line = json.dumps({"ts": 1763373600.0, "uid": "Cj", "id.orig_h": "10.0.0.1", "id.orig_p": 5000,
                           "id.resp_h": "10.0.0.2", "id.resp_p": 22, "proto": "tcp", "orig_pkts": 3})
        flow = ConnLogParser().parse_line(line)
        self.assertEqual((flow["flow_id"], flow["dst_port"], flow["packets_sent"], flow["bytes_sent"]),
                         ("Cj", 22, 3.0, None))

    def test_lines_before_header_and_malformed_rows_are_skipped(self):
        p = ConnLogParser()
        self.assertIsNone(p.parse_line("1\t2\t3"))
        with open(FIXTURE, encoding="utf-8") as f:
            for line in f.read().splitlines()[:8]:
                p.parse_line(line)
        self.assertIsNone(p.parse_line("only\ttwo"))

    def test_history_flags(self):
        self.assertEqual(history_to_flags("Sr"), "SYN,RST")
        self.assertIsNone(history_to_flags(None))

    def test_scan_in_fixture_is_detected(self):
        flows = load_conn_log(FIXTURE)
        hits = detect_port_scans(flows, Config(logs_dir=tempfile.mkdtemp()).rules)
        scanned = {flows[i]["flow_id"] for i in hits}
        self.assertEqual(scanned, {f"Cscan{i:02d}" for i in range(12)})
        self.assertEqual({h["subtype"] for h in hits.values()}, {"Vertical"})

    def test_answered_requests_are_not_scan_probes(self):
        # One host asking 12 DNS servers (answers carry payload) is not a scan.
        flows = load_conn_log(FIXTURE)
        dns = [dict(flows[1], flow_id=f"d{i}", dst_ip=f"192.0.2.{i}", timestamp=f"2025-11-17T10:00:{i:02d}Z")
               for i in range(12)]
        self.assertEqual(detect_port_scans(dns, Config(logs_dir=tempfile.mkdtemp()).rules), {})

    def test_icmp_is_not_scored_by_model(self):
        from nids_agent.engine import NIDSAgent
        flows = load_conn_log(FIXTURE)
        icmp = dict(flows[0], flow_id="icmp1", protocol="ICMP", src_port=3, dst_port=3)
        tmp = tempfile.mkdtemp()
        NIDSAgent(Config(logs_dir=tmp, data_dir=DATA)).process_batch([icmp])
        with open(os.path.join(tmp, "decision_log.jsonl"), encoding="utf-8") as f:
            step = next(s for d in map(json.loads, f) if "steps" in d for s in d["steps"] if s["stage"] == "ml_inference")
        self.assertEqual(step["status"], "skipped")


if __name__ == "__main__":
    unittest.main()
