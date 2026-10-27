"""Async token-bucket rate limiter."""

from __future__ import annotations

import asyncio
import time

class TokenBucket:
    """Classic token bucket: `rate` tokens/sec, capped at `burst`."""

    def __init__(self, rate: float, burst: int = 1) -> None:
        self.rate = max(rate, 0.01)
        self.burst = max(burst, 1)
        self._tokens = float(self.burst)
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: float = 1.0) -> None:
        while True:
            async with self._lock:
                now = time.monotonic()
                elapsed = now - self._updated
                self._updated = now
                self._tokens = min(self.burst, self._tokens + elapsed * self.rate)
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return
                deficit = tokens - self._tokens
                wait = deficit / self.rate
            await asyncio.sleep(wait)
