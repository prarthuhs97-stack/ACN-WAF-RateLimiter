"""Thread-safe, in-memory metrics for comparing the two pipeline orders.

This module only COUNTS and TIMES things. It never decides whether a request
is allowed, so it is separate from the rate limiter, the WAF and the pipeline.

Typical use (see server.py):

    metrics = Metrics(pipeline_order="rate_limit_first")
    metrics.record_request()                          # a request arrived
    metrics.record_waf_block("xss", "rule", "query")  # only if the WAF blocked
    metrics.record_response(403, latency_s=0.0012)    # final HTTP status
    print(metrics.snapshot())                         # plain dict copy

Latency samples are kept in a list. That is fine for short, controlled
experiments; a long-running production server would need something smarter.
"""

import math
import threading
import time

# Attack-type names used by waf.py. Anything else is counted as "other"
# (for example encoding_evasion). tests/test_metrics.py checks these stay in
# sync with waf.py.
ATTACK_SQLI = "sql_injection"
ATTACK_XSS = "xss"
ATTACK_TRAVERSAL = "path_traversal"


class Metrics:
    def __init__(self, pipeline_order="unknown", clock=time.monotonic):
        self._lock = threading.Lock()
        self._clock = clock
        self._pipeline_order = pipeline_order
        self._reset_counters()

    def _reset_counters(self):
        self._total_requests = 0
        self._status_200 = 0
        self._status_403 = 0
        self._status_429 = 0
        self._error_requests = 0       # any other status >= 400 (400, 408, 431...)
        self._waf_blocked = 0
        self._rate_limited = 0
        self._waf_sql_injection = 0
        self._waf_xss = 0
        self._waf_path_traversal = 0
        self._waf_other = 0
        self._waf_by_rule = {}
        self._waf_by_location = {}
        self._latencies = []           # seconds, one per timed request
        self._first_request_at = None  # monotonic time of the first request
        self._last_response_at = None  # monotonic time of the latest response

    # ---------------- recording ----------------

    def record_request(self):
        """Call once for every request that arrives (including malformed ones)."""
        with self._lock:
            self._total_requests += 1
            if self._first_request_at is None:
                self._first_request_at = self._clock()

    def record_response(self, status, latency_s=None):
        """Call once with the final HTTP status.

        latency_s is the processing time in seconds. Leave it as None when the
        request was never timed (for example it failed to parse).
        """
        with self._lock:
            if status == 200:
                self._status_200 += 1
            elif status == 403:
                self._status_403 += 1
            elif status == 429:
                self._status_429 += 1
            elif status >= 400:
                self._error_requests += 1
            if latency_s is not None:
                self._latencies.append(latency_s)
            self._last_response_at = self._clock()

    def record_waf_block(self, attack_type, rule=None, location=None):
        """Call when the WAF blocks a request (the 403 itself goes through
        record_response)."""
        with self._lock:
            self._waf_blocked += 1
            if attack_type == ATTACK_SQLI:
                self._waf_sql_injection += 1
            elif attack_type == ATTACK_XSS:
                self._waf_xss += 1
            elif attack_type == ATTACK_TRAVERSAL:
                self._waf_path_traversal += 1
            else:
                self._waf_other += 1
            if rule:
                self._waf_by_rule[rule] = self._waf_by_rule.get(rule, 0) + 1
            if location:
                self._waf_by_location[location] = (
                    self._waf_by_location.get(location, 0) + 1
                )

    def record_rate_limit(self):
        """Call when the rate limiter rejects a request (the 429 itself goes
        through record_response)."""
        with self._lock:
            self._rate_limited += 1

    # ---------------- reading ----------------

    def snapshot(self):
        """Return a new dict with the current numbers.

        Everything returned is a copy, so changing it cannot affect the
        metrics.
        """
        with self._lock:
            samples = list(self._latencies)
            total_time = sum(samples)
            count = len(samples)

            if self._first_request_at is None or self._last_response_at is None:
                elapsed = 0.0
            else:
                elapsed = self._last_response_at - self._first_request_at
            throughput = self._total_requests / elapsed if elapsed > 0 else 0.0

            return {
                "pipeline_order": self._pipeline_order,
                "total_requests": self._total_requests,
                "status_200": self._status_200,
                "status_403": self._status_403,
                "status_429": self._status_429,
                "error_requests": self._error_requests,
                "waf_blocked": self._waf_blocked,
                "rate_limited": self._rate_limited,
                "waf_sql_injection": self._waf_sql_injection,
                "waf_xss": self._waf_xss,
                "waf_path_traversal": self._waf_path_traversal,
                "waf_other": self._waf_other,
                "waf_by_rule": dict(self._waf_by_rule),
                "waf_by_location": dict(self._waf_by_location),
                "latency_samples": count,
                "total_processing_time_ms": round(total_time * 1000, 3),
                "avg_latency_ms": round(total_time / count * 1000, 3) if count else 0.0,
                "p95_latency_ms": round(_p95(samples) * 1000, 3),
                "elapsed_s": round(elapsed, 3),
                "throughput_rps": round(throughput, 3),
            }


def _p95(samples):
    """95th percentile using the nearest-rank method (0.0 if no samples)."""
    if not samples:
        return 0.0
    ordered = sorted(samples)
    rank = math.ceil(0.95 * len(ordered))  # 1-based position
    return ordered[rank - 1]