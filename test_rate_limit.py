import time
from functools import wraps
from urllib.parse import urlparse
from collections import defaultdict

class RateLimiter:
    """单例模式限流器：按域名控制每分钟请求次数"""
    _instance = None
    _domain_stats = defaultdict(lambda: {
        "count": 0,
        "reset_time": time.time(),
        "limit": 30
    })

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def set_limit(self, domain: str, limit: int):
        self._domain_stats[domain]["limit"] = limit

    def _get_domain(self, url: str) -> str:
        return urlparse(url).netloc

    def is_allowed(self, url: str) -> bool:
        domain = self._get_domain(url)
        now = time.time()
        if now - self._domain_stats[domain]["reset_time"] >= 60:
            self._domain_stats[domain]["count"] = 0
            self._domain_stats[domain]["reset_time"] = now
        if self._domain_stats[domain]["count"] < self._domain_stats[domain]["limit"]:
            self._domain_stats[domain]["count"] += 1
            return True
        return False

# 测试
if __name__ == "__main__":
    limiter = RateLimiter()
    test_url = "https://api.stock.com/data"
    for i in range(35):
        allowed = limiter.is_allowed(test_url)
        print(f"第{i+1}次请求：{'✅ 允许' if allowed else '❌ 拒绝'}")