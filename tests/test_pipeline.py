import os
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "server"))

from pipeline import Pipeline, RATE_LIMIT_FIRST, WAF_FIRST  # noqa: E402
from rate_limiter import RateLimiter  # noqa: E402
from waf import WAF  # noqa: E402

REQ = SimpleNamespace(client_ip="10.0.0.1")
BENIGN = SimpleNamespace(path="/", query="name=John", body="", flags=set())
MALICIOUS = SimpleNamespace(path="/", query="id=1' OR 1=1--", body="", flags=set())


class FakeClock:
    def __call__(self):
        return 1000.0


class SpyLimiter:
    def __init__(self, inner, log):
        self.inner, self.log = inner, log

    def allow(self, cid):
        self.log.append("rate_limiter")
        return self.inner.allow(cid)


class SpyWAF:
    def __init__(self, inner, log):
        self.inner, self.log = inner, log

    def inspect(self, n):
        self.log.append("waf")
        return self.inner.inspect(n)


def make(order, capacity=3):
    log = []
    limiter = SpyLimiter(RateLimiter(rate=0, capacity=capacity, clock=FakeClock()), log)
    waf = SpyWAF(WAF(), log)
    return Pipeline(limiter, waf, order), log


class TestPipelineConfig(unittest.TestCase):
    def test_default_order_env_unset(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("PIPELINE_ORDER", None)
            self.assertEqual(Pipeline.from_env(None, None).order, RATE_LIMIT_FIRST)

    def test_env_waf_first(self):
        with mock.patch.dict(os.environ, {"PIPELINE_ORDER": "waf_first"}):
            self.assertEqual(Pipeline.from_env(None, None).order, WAF_FIRST)

    def test_env_case_and_whitespace(self):
        with mock.patch.dict(os.environ, {"PIPELINE_ORDER": "  WAF_First "}):
            self.assertEqual(Pipeline.from_env(None, None).order, WAF_FIRST)

    def test_invalid_env_raises(self):
        with mock.patch.dict(os.environ, {"PIPELINE_ORDER": "banana"}):
            with self.assertRaises(ValueError):
                Pipeline.from_env(None, None)

    def test_invalid_constructor_raises(self):
        with self.assertRaises(ValueError):
            Pipeline(None, None, "nope")

    def test_default_constructor_is_mode_a(self):
        self.assertEqual(Pipeline(None, None).order, RATE_LIMIT_FIRST)


class TestPipelineBehavior(unittest.TestCase):
    def test_call_order_mode_a(self):
        p, log = make(RATE_LIMIT_FIRST)
        self.assertTrue(p.process(REQ, BENIGN).allowed)
        self.assertEqual(log, ["rate_limiter", "waf"])

    def test_call_order_mode_b(self):
        p, log = make(WAF_FIRST)
        self.assertTrue(p.process(REQ, BENIGN).allowed)
        self.assertEqual(log, ["waf", "rate_limiter"])

    def test_benign_allowed_both(self):
        for order in (RATE_LIMIT_FIRST, WAF_FIRST):
            with self.subTest(order=order):
                p, _ = make(order)
                r = p.process(REQ, BENIGN)
                self.assertEqual((r.allowed, r.status, r.stage), (True, 200, None))

    def test_mode_a_malicious_consumes_tokens(self):
        p, log = make(RATE_LIMIT_FIRST, capacity=3)
        for _ in range(3):
            self.assertEqual(p.process(REQ, MALICIOUS).status, 403)
        # bucket drained by attack traffic -> legitimate request is rate limited
        self.assertEqual(p.process(REQ, BENIGN).status, 429)

    def test_mode_b_malicious_does_not_consume_tokens(self):
        p, log = make(WAF_FIRST, capacity=3)
        for _ in range(10):
            self.assertEqual(p.process(REQ, MALICIOUS).status, 403)
        self.assertNotIn("rate_limiter", log)
        # bucket untouched -> legitimate traffic still gets its full burst
        for _ in range(3):
            self.assertEqual(p.process(REQ, BENIGN).status, 200)
        self.assertEqual(p.process(REQ, BENIGN).status, 429)

    def test_exhausted_bucket_malicious_request(self):
        pa, la = make(RATE_LIMIT_FIRST, capacity=2)
        pb, lb = make(WAF_FIRST, capacity=2)
        for p in (pa, pb):
            for _ in range(2):
                p.process(REQ, BENIGN)           # drain bucket
        la.clear(); lb.clear()
        ra = pa.process(REQ, MALICIOUS)
        rb = pb.process(REQ, MALICIOUS)
        # Mode A: limiter rejects first, WAF never sees it
        self.assertEqual((ra.status, ra.stage), (429, "rate_limiter"))
        self.assertEqual(la, ["rate_limiter"])
        # Mode B: WAF rejects first, limiter never sees it
        self.assertEqual((rb.status, rb.stage), (403, "waf"))
        self.assertEqual(lb, ["waf"])

    def test_exhausted_bucket_benign_both_429(self):
        for order in (RATE_LIMIT_FIRST, WAF_FIRST):
            with self.subTest(order=order):
                p, _ = make(order, capacity=1)
                p.process(REQ, BENIGN)
                r = p.process(REQ, BENIGN)
                self.assertEqual((r.allowed, r.status, r.stage), (False, 429, "rate_limiter"))

    def test_result_fields(self):
        p, _ = make(WAF_FIRST, capacity=1)
        r = p.process(REQ, MALICIOUS)
        self.assertEqual((r.status, r.stage), (403, "waf"))
        self.assertEqual(r.waf.attack_type, "sql_injection")
        p.process(REQ, BENIGN)
        r = p.process(REQ, BENIGN)
        self.assertEqual(r.status, 429)
        self.assertIsNone(r.waf)


if __name__ == "__main__":
    unittest.main()