from prometheus_client import Counter, Histogram


API_REQUESTS_TOTAL = Counter(
    "api_requests_total",
    "Total number of API requests.",
    ["method", "endpoint", "status_code"],
)

API_REQUEST_DURATION_SECONDS = Histogram(
    "api_request_duration_seconds",
    "API request duration in seconds.",
    ["method", "endpoint"],
)

REDIS_CACHE_HITS_TOTAL = Counter(
    "redis_cache_hits_total",
    "Total Redis cache hits.",
)

REDIS_CACHE_MISSES_TOTAL = Counter(
    "redis_cache_misses_total",
    "Total Redis cache misses.",
)

SECURITY_ALERTS_TOTAL = Counter(
    "security_alerts_total",
    "Total detected security alerts.",
    ["alert_type", "severity"],
)