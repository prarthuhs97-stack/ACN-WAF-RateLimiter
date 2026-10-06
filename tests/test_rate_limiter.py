import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "server"))

from rate_limiter import RateLimiter  # noqa: E402


class FakeClock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


class TestRateLimiter(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()

    def make(self, rate=1, capacity=5, **kw):
        return RateLimiter(rate=rate, capacity=capacity, clock=self.clock, **kw)

    def test_initial_burst_capacity(self):
        rl = self.make(rate=1, capacity=5)
        self.assertTrue(all(rl.allow("a").allowed for _ in range(5)))

    def test_rejection_after_exhausted(self):
        rl = self.make(rate=1, capacity=3)
        for _ in range(3):
            self.assertTrue(rl.allow("a").allowed)
        d = rl.allow("a")
        self.assertFalse(d.allowed)
        self.assertGreaterEqual(d.retry_after, 1)

    def test_refill_over_time(self):
        rl = self.make(rate=2, capacity=4)
        for _ in range(4):
            rl.allow("a")
        self.assertFalse(rl.allow("a").allowed)
        self.clock.advance(1.0)  # +2 tokens
        self.assertTrue(rl.allow("a").allowed)
        self.assertTrue(rl.allow("a").allowed)
        self.assertFalse(rl.allow("a").allowed)

    def test_partial_refill(self):
        rl = self.make(rate=1, capacity=1)
        self.assertTrue(rl.allow("a").allowed)
        self.clock.advance(0.5)
        self.assertFalse(rl.allow("a").allowed)
        self.clock.advance(0.5)
        self.assertTrue(rl.allow("a").allowed)

    def test_capacity_never_exceeded(self):
        rl = self.make(rate=10, capacity=3)
        rl.allow("a")
        self.clock.advance(1000)  # would refill far past capacity
        allowed = sum(rl.allow("a").allowed for _ in range(10))
        self.assertEqual(allowed, 3)

    def test_separate_clients(self):
        rl = self.make(rate=0, capacity=2)
        rl.allow("a"); rl.allow("a")
        self.assertFalse(rl.allow("a").allowed)
        self.assertTrue(rl.allow("b").allowed)
        self.assertTrue(rl.allow("b").allowed)
        self.assertFalse(rl.allow("b").allowed)

    def test_thread_safety(self):
        rl = self.make(rate=0, capacity=100)  # no refill -> exactly 100 allowed
        results = []
        lock = threading.Lock()

        def worker():
            local = [rl.allow("shared").allowed for _ in range(50)]
            with lock:
                results.extend(local)

        threads = [threading.Thread(target=worker) for _ in range(20)]
        for t in threads: t.start()
        for t in threads: t.join()
        self.assertEqual(len(results), 1000)
        self.assertEqual(sum(results), 100)

    def test_thread_safety_many_clients(self):
        rl = self.make(rate=0, capacity=10)
        counts = {}
        lock = threading.Lock()

        def worker(cid):
            n = sum(rl.allow(cid).allowed for _ in range(30))
            with lock:
                counts[cid] = n

        threads = [threading.Thread(target=worker, args=("c%d" % i,)) for i in range(30)]
        for t in threads: t.start()
        for t in threads: t.join()
        self.assertTrue(all(v == 10 for v in counts.values()))

    def test_configurable_rate_capacity(self):
        slow = self.make(rate=1, capacity=2)
        fast = self.make(rate=10, capacity=20)
        self.assertEqual(sum(slow.allow("a").allowed for _ in range(30)), 2)
        self.assertEqual(sum(fast.allow("a").allowed for _ in range(30)), 20)
        self.clock.advance(1)
        self.assertEqual(sum(slow.allow("a").allowed for _ in range(30)), 1)
        self.assertEqual(sum(fast.allow("a").allowed for _ in range(30)), 10)

    def test_invalid_config(self):
        with self.assertRaises(ValueError):
            RateLimiter(rate=-1, capacity=5)
        with self.assertRaises(ValueError):
            RateLimiter(rate=1, capacity=0)

    def test_idle_cleanup(self):
        rl = self.make(rate=1, capacity=2, idle_ttl=10, cleanup_interval=5)
        rl.allow("a"); rl.allow("b")
        self.assertEqual(rl.client_count(), 2)
        self.clock.advance(100)
        rl.allow("c")
        self.assertEqual(rl.client_count(), 1)

    def test_max_clients_cap(self):
        rl = self.make(rate=1, capacity=2, max_clients=3)
        for i in range(10):
            rl.allow("c%d" % i)
        self.assertEqual(rl.client_count(), 3)


if __name__ == "__main__":
    unittest.main()