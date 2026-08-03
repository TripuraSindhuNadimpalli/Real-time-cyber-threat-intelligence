import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class Settings:
    # Kafka
    kafka_bootstrap_servers: str
    kafka_topic: str
    kafka_consumer_group: str

    # PostgreSQL
    postgres_host: str
    postgres_port: int
    postgres_db: str
    postgres_user: str
    postgres_password: str

    # Redis
    redis_host: str
    redis_port: int
    redis_db: int
    redis_cache_ttl: int


settings = Settings(
    # Kafka
    kafka_bootstrap_servers=os.getenv(
        "KAFKA_BOOTSTRAP_SERVERS",
        "localhost:9092",
    ),
    kafka_topic=os.getenv(
        "KAFKA_TOPIC",
        "security-events",
    ),
    kafka_consumer_group=os.getenv(
        "KAFKA_CONSUMER_GROUP",
        "cyber-threat-consumer",
    ),

    # PostgreSQL
    postgres_host=os.getenv(
        "POSTGRES_HOST",
        "localhost",
    ),
    postgres_port=int(
        os.getenv("POSTGRES_PORT", "55432")
    ),
    postgres_db=os.getenv(
        "POSTGRES_DB",
        "cyber_threat_db",
    ),
    postgres_user=os.getenv(
        "POSTGRES_USER",
        "cyber_user",
    ),
    postgres_password=os.getenv(
        "POSTGRES_PASSWORD",
        "cyber_password",
    ),

    # Redis
    redis_host=os.getenv(
        "REDIS_HOST",
        "localhost",
    ),
    redis_port=int(
        os.getenv("REDIS_PORT", "6379")
    ),
    redis_db=int(
        os.getenv("REDIS_DB", "0")
    ),
    redis_cache_ttl=int(
        os.getenv("REDIS_CACHE_TTL", "60")
    ),
)