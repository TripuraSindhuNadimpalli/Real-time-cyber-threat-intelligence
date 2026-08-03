import json
import logging

import redis

from config.settings import settings

logger = logging.getLogger(__name__)


class RedisClient:
    def __init__(self) -> None:
        self.client = redis.Redis(
            host=settings.redis_host,
            port=settings.redis_port,
            db=settings.redis_db,
            decode_responses=True,
        )

    def get(self, key: str):
        value = self.client.get(key)

        if value is None:
            logger.info("Redis cache miss | key=%s", key)
            return None

        logger.info("Redis cache hit | key=%s", key)
        return json.loads(value)

    def set(self, key: str, value) -> None:
        self.client.set(
            name=key,
            value=json.dumps(value, default=str),
            ex=settings.redis_cache_ttl,
        )

        logger.info(
            "Cached value in Redis | key=%s | ttl=%ss",
            key,
            settings.redis_cache_ttl,
        )

    def delete(self, key: str) -> None:
        self.client.delete(key)

        logger.info("Deleted Redis key=%s", key)

    def ping(self) -> bool:
        return self.client.ping()