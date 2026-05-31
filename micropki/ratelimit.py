import time
import threading


class TokenBucket:
    def __init__(self, rate: float, burst: int):
        self.rate = float(rate)
        self.burst = int(burst)
        self.tokens = float(burst)
        self.updated_at = time.monotonic()
        self.lock = threading.Lock()

    def allow(self) -> tuple[bool, int]:
        with self.lock:
            now = time.monotonic()
            elapsed = now - self.updated_at
            self.updated_at = now

            self.tokens = min(self.burst, self.tokens + elapsed * self.rate)

            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return True, 0

            retry_after = max(1, int((1.0 - self.tokens) / self.rate)) if self.rate > 0 else 1
            return False, retry_after


class IPRateLimiter:
    def __init__(self, rate: float, burst: int):
        self.rate = rate
        self.burst = burst
        self.buckets = {}
        self.lock = threading.Lock()

    def allow(self, ip: str) -> tuple[bool, int]:
        with self.lock:
            if ip not in self.buckets:
                self.buckets[ip] = TokenBucket(self.rate, self.burst)
            bucket = self.buckets[ip]
        return bucket.allow()