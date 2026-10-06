import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "server"))

import waf  # noqa: E402
from metrics import Metrics, ATTACK_SQLI, ATTACK_XSS, ATTACK_TRAVERSAL  # noqa: E402
from pipeline import RATE_LIMIT_FIRST, WAF_FIRST  # noqa: E402


class FakeClock:
    """A clock we move by hand so throughput tests are exact."""

    def __init__(self):
        self.now = 100.0

    def __call__(self):
        return self.now


class MetricsTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.m = Metrics(RATE_LIMIT_FIRST, clock=self.clock)

    # 1. initial values
    def test_initial_metrics_are_zero(self):
        s = self.m.snapshot()
        for key in (
            "total_requests", "status_200", "status_403", "status_429",
            "error_requests", "waf_blocked", "rate_limited",
            "waf_sql_injection", "waf_xss", "waf_path_traversal", "waf_other",
            "latency_samples", "total_processing_time_ms",
            "avg_latency_ms", "p95_latency_ms", "throughput_rps",
        ):
            self.assertEqual(s[key], 0, key)
        self.assertEqual(s["waf_by_rule"], {})
        self.assertEqual(s["waf_by_location"], {})

    # 2. successful requests
    def test_record_successful_requests(self):
        for _ in range(3):
            self.m.record_request()
            self.m.record_response(200, 0.001)
        s = self.m.snapshot()
        self.assertEqual(s["total_requests"], 3)
        self.assertEqual(s["status_200"], 3)
        self.assertEqual(s["status_403"], 0)
        self.assertEqual(s["status_429"], 0)

    # 3. WAF blocks
    def test_record_waf_block(self):
        self.m.record_request()
        self.m.record_waf_block(ATTACK_SQLI, "sqli_tautology_quote", "query")
        self.m.record_response(403, 0.002)
        s = self.m.snapshot()
        self.assertEqual(s["status_403"], 1)
        self.assertEqual(s["waf_blocked"], 1)
        self.assertEqual(s["waf_by_rule"], {"sqli_tautology_quote": 1})
        self.assertEqual(s["waf_by_location"], {"query": 1})

    # 4. rate limits
    def test_record_rate_limit(self):
        self.m.record_request()
        self.m.record_rate_limit()
        self.m.record_response(429, 0.0005)
        s = self.m.snapshot()
        self.assertEqual(s["status_429"], 1)
        self.assertEqual(s["rate_limited"], 1)
        self.assertEqual(s["waf_blocked"], 0)

    def test_error_statuses_are_counted_separately(self):
        for status in (400, 408, 431):
            self.m.record_request()
            self.m.record_response(status)  # not timed
        s = self.m.snapshot()
        self.assertEqual(s["error_requests"], 3)
        self.assertEqual(s["total_requests"], 3)
        self.assertEqual(s["latency_samples"], 0)
        self.assertEqual(s["status_200"] + s["status_403"] + s["status_429"], 0)

    # 5. attack types
    def test_attack_type_counters(self):
        self.m.record_waf_block(ATTACK_SQLI, "r1", "query")
        self.m.record_waf_block(ATTACK_SQLI, "r1", "body")
        self.m.record_waf_block(ATTACK_XSS, "r2", "query")
        self.m.record_waf_block(ATTACK_TRAVERSAL, "r3", "path")
        self.m.record_waf_block("encoding_evasion", "r4", "path")
        self.m.record_waf_block(None)
        s = self.m.snapshot()
        self.assertEqual(s["waf_sql_injection"], 2)
        self.assertEqual(s["waf_xss"], 1)
        self.assertEqual(s["waf_path_traversal"], 1)
        self.assertEqual(s["waf_other"], 2)
        self.assertEqual(s["waf_blocked"], 6)
        self.assertEqual(s["waf_by_rule"], {"r1": 2, "r2": 1, "r3": 1, "r4": 1})
        self.assertEqual(s["waf_by_location"], {"query": 2, "body": 1, "path": 2})

    def test_attack_type_names_match_waf_module(self):
        self.assertEqual(ATTACK_SQLI, waf.SQLI)
        self.assertEqual(ATTACK_XSS, waf.XSS)
        self.assertEqual(ATTACK_TRAVERSAL, waf.TRAVERSAL)

    # 6. average latency
    def test_average_latency(self):
        for seconds in (0.010, 0.020, 0.030):
            self.m.record_request()
            self.m.record_response(200, seconds)
        s = self.m.snapshot()
        self.assertEqual(s["latency_samples"], 3)
        self.assertAlmostEqual(s["avg_latency_ms"], 20.0, places=3)
        self.assertAlmostEqual(s["total_processing_time_ms"], 60.0, places=3)

    # 7. p95 latency (nearest rank)
    def test_p95_latency_with_100_samples(self):
        for ms in range(1, 101):  # 1..100 ms
            self.m.record_response(200, ms / 1000.0)
        self.assertAlmostEqual(self.m.snapshot()["p95_latency_ms"], 95.0, places=3)

    def test_p95_with_one_and_few_samples(self):
        self.m.record_response(200, 0.005)
        self.assertAlmostEqual(self.m.snapshot()["p95_latency_ms"], 5.0, places=3)
        for ms in (1, 2, 3, 4):
            self.m.record_response(200, ms / 1000.0)
        # 5 samples -> rank ceil(4.75) = 5 -> the largest value
        self.assertAlmostEqual(self.m.snapshot()["p95_latency_ms"], 5.0, places=3)

    def test_p95_ignores_arrival_order(self):
        for ms in (100, 1, 50, 2, 3):
            self.m.record_response(200, ms / 1000.0)
        self.assertAlmostEqual(self.m.snapshot()["p95_latency_ms"], 100.0, places=3)

    # throughput
    def test_throughput(self):
        self.m.record_request()          # t = 100
        self.clock.now = 102.0
        for _ in range(3):
            self.m.record_request()
        self.m.record_response(200, 0.001)  # last response at t = 102
        s = self.m.snapshot()
        self.assertEqual(s["total_requests"], 4)
        self.assertAlmostEqual(s["elapsed_s"], 2.0)
        self.assertAlmostEqual(s["throughput_rps"], 2.0)

    def test_throughput_is_zero_when_no_time_has_passed(self):
        self.m.record_request()
        self.m.record_response(200, 0.001)
        self.assertEqual(self.m.snapshot()["throughput_rps"], 0.0)

    # 8. snapshot is a copy
    def test_snapshot_does_not_expose_internal_state(self):
        self.m.record_waf_block(ATTACK_XSS, "rule_x", "query")
        self.m.record_request()
        self.m.record_response(403, 0.01)

        first = self.m.snapshot()
        first["total_requests"] = 999
        first["waf_by_rule"]["rule_x"] = 999
        first["waf_by_rule"]["new_rule"] = 1
        first["waf_by_location"].clear()
        first["pipeline_order"] = "hacked"

        second = self.m.snapshot()
        self.assertEqual(second["total_requests"], 1)
        self.assertEqual(second["waf_by_rule"], {"rule_x": 1})
        self.assertEqual(second["waf_by_location"], {"query": 1})
        self.assertEqual(second["pipeline_order"], RATE_LIMIT_FIRST)
        self.assertIsNot(first, second)

    # 9. concurrency
    def test_concurrent_updates_are_safe(self):
        threads_count, per_thread = 8, 500
        m = Metrics(WAF_FIRST)

        def worker(index):
            for _ in range(per_thread):
                m.record_request()
                if index % 2 == 0:
                    m.record_waf_block(ATTACK_SQLI, "rule", "query")
                    m.record_response(403, 0.001)
                else:
                    m.record_rate_limit()
                    m.record_response(429, 0.002)

        threads = [threading.Thread(target=worker, args=(i,))
                   for i in range(threads_count)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        s = m.snapshot()
        half = (threads_count // 2) * per_thread
        self.assertEqual(s["total_requests"], threads_count * per_thread)
        self.assertEqual(s["status_403"], half)
        self.assertEqual(s["status_429"], half)
        self.assertEqual(s["waf_blocked"], half)
        self.assertEqual(s["waf_sql_injection"], half)
        self.assertEqual(s["rate_limited"], half)
        self.assertEqual(s["latency_samples"], threads_count * per_thread)
        self.assertEqual(s["waf_by_rule"], {"rule": half})

    # 10. pipeline order
    def test_pipeline_order_is_represented(self):
        self.assertEqual(Metrics(RATE_LIMIT_FIRST).snapshot()["pipeline_order"],
                         "rate_limit_first")
        self.assertEqual(Metrics(WAF_FIRST).snapshot()["pipeline_order"],
                         "waf_first")

    def test_pipeline_order_defaults_to_unknown(self):
        self.assertEqual(Metrics().snapshot()["pipeline_order"], "unknown")


if __name__ == "__main__":
    unittest.main()