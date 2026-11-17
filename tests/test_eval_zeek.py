import os
import sys
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

from eval_zeek import cic_start_candidates, endpoint_key, label_flow  # noqa: E402


def utc(*args):
    return datetime(*args, tzinfo=timezone.utc).timestamp()


class EvalZeekTest(unittest.TestCase):
    def test_timestamp_is_local_adt_and_12_hour_ambiguous(self):
        # '3:30' on 7/7/2017 ADT (UTC-3) can be 06:30 or 18:30 UTC.
        self.assertEqual(sorted(cic_start_candidates("7/7/2017 3:30")),
                         [utc(2017, 7, 7, 6, 30), utc(2017, 7, 7, 18, 30)])
        self.assertEqual(cic_start_candidates("7/7/2017 15:30"), [utc(2017, 7, 7, 18, 30)])

    def test_endpoint_key_ignores_direction(self):
        self.assertEqual(endpoint_key("TCP", "10.0.0.1", 443, "10.0.0.2", "5000"),
                         endpoint_key("TCP", "10.0.0.2", "5000", "10.0.0.1", 443))

    def test_label_flow_matches_by_endpoints_and_time(self):
        index = {endpoint_key("TCP", "172.16.0.1", 80, "192.168.10.50", 4000): [
            (cic_start_candidates("7/7/2017 3:56"), "BENIGN"),
            (cic_start_candidates("7/7/2017 3:57"), "DDoS"),
        ]}
        flow = {"protocol": "TCP", "src_ip": "192.168.10.50", "src_port": 4000, "dst_ip": "172.16.0.1",
                "dst_port": 80, "timestamp": "2017-07-07T18:56:30Z", "duration": 50.0}
        self.assertEqual(label_flow(flow, index), "DDoS")  # any attack among matches wins
        early = dict(flow, timestamp="2017-07-07T12:00:00Z", duration=1.0)
        self.assertIsNone(label_flow(early, index))  # same endpoints, different time
        self.assertIsNone(label_flow(dict(flow, dst_port=81), index))


if __name__ == "__main__":
    unittest.main()
