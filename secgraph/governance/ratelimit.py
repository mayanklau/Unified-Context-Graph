"""Token-bucket rate limiting, per principal.

State is per process. With several replicas each enforces its own bucket, so
the effective limit is ``replicas × limit``; put a shared limit on the ingress
if a hard global ceiling is required (see docs/OPERATIONS.md).
"""

from __future__ import annotations

import threading
import time

from secgraph.errors import RateLimited
from secgraph.observability import RATE_LIMITED


class RateLimiter:
    def __init__(self, per_minute: int, burst: int, *, max_keys: int = 50_000):
        self.rate = max(per_minute, 1) / 60.0
        self.capacity = float(max(burst, 1))
        self.max_keys = max_keys
        self._buckets: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def check(self, key: str, cost: float = 1.0) -> None:
        now = time.monotonic()
        with self._lock:
            tokens, updated = self._buckets.get(key, (self.capacity, now))
            tokens = min(self.capacity, tokens + (now - updated) * self.rate)
            if tokens < cost:
                self._buckets[key] = (tokens, now)
                RATE_LIMITED.inc()
                retry_after = max(1, int((cost - tokens) / self.rate) + 1)
                raise RateLimited("rate limit exceeded", detail={"retry_after_seconds": retry_after})
            self._buckets[key] = (tokens - cost, now)
            if len(self._buckets) > self.max_keys:
                self._evict(now)

    def _evict(self, now: float) -> None:
        # Drop buckets that have fully refilled: they carry no information.
        full_after = self.capacity / self.rate
        stale = [k for k, (_tokens, updated) in self._buckets.items() if now - updated > full_after]
        for key in stale:
            del self._buckets[key]
        if len(self._buckets) > self.max_keys:
            for key in list(self._buckets)[: len(self._buckets) - self.max_keys]:
                del self._buckets[key]
