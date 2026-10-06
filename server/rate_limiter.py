"""Thread-safe per-client Token Bucket rate limiter (standalone module)."""

import math
import os
import threading
import time
from collections import OrderedDict, namedtuple

Decision = namedtuple("Decision", ["allowed", "tokens", "retry_after"])


class _Bucket:
    __slots__ = ("tokens", "last")

    def __init__(self, tokens, last):
        self.tokens = tokens
        self.last = last


class RateLimiter:
    """
    rate     : tokens added per second (>= 0)
    capacity : max tokens / burst size (> 0)
    clock    : monotonic time source (injectable for tests)
    idle_ttl : seconds a client may be idle before its bucket is dropped
    max_clients : hard cap on tracked buckets (LRU eviction)
    """

    def __init__(self, rate=5.0, capacity=10, clock=time.monotonic,
                 idle_ttl=300.0, cleanup_interval=30.0, max_clients=10000):
        if rate < 0:
            raise ValueError("rate must be >= 0")
        if capacity <= 0:
            raise ValueError("capacity must be > 0")
        if max_clients <= 0:
            raise ValueError("max_clients must be > 0")
        self.rate = float(rate)
        self.capacity = float(capacity)
        self._clock = clock
        # never evict a bucket before it would have fully refilled
        refill_time = (self.capacity / self.rate) if self.rate > 0 else 0.0
        self._idle_ttl = max(float(idle_ttl), refill_time)
        self._cleanup_interval = float(cleanup_interval)
        self._max_clients = int(max_clients)
        self._buckets = OrderedDict()  # client_id -> _Bucket, LRU order
        self._lock = threading.Lock()
        self._last_cleanup = self._clock()

    @classmethod
    def from_env(cls):
        """RATE_LIMIT_RATE, RATE_LIMIT_CAPACITY env vars (for experiments)."""
        return cls(rate=float(os.environ.get("RATE_LIMIT_RATE", "5")),
                   capacity=float(os.environ.get("RATE_LIMIT_CAPACITY", "10")))

    def allow(self, client_id):
        """Consume one token for client_id. Returns Decision."""
        with self._lock:
            now = self._clock()
            self._maybe_cleanup(now)

            b = self._buckets.get(client_id)
            if b is None:
                b = _Bucket(self.capacity, now)
                self._buckets[client_id] = b
                if len(self._buckets) > self._max_clients:
                    self._buckets.popitem(last=False)
            else:
                elapsed = max(0.0, now - b.last)
                b.tokens = min(self.capacity, b.tokens + elapsed * self.rate)
                b.last = now
                self._buckets.move_to_end(client_id)

            if b.tokens >= 1.0:
                b.tokens -= 1.0
                return Decision(True, b.tokens, 0)

            if self.rate > 0:
                retry = max(1, math.ceil((1.0 - b.tokens) / self.rate))
            else:
                retry = None
            return Decision(False, b.tokens, retry)

    def client_count(self):
        with self._lock:
            return len(self._buckets)

    def _maybe_cleanup(self, now):
        # caller holds the lock
        if now - self._last_cleanup < self._cleanup_interval:
            return
        self._last_cleanup = now
        while self._buckets:
            cid, b = next(iter(self._buckets.items()))
            if now - b.last > self._idle_ttl:
                del self._buckets[cid]
            else:
                break