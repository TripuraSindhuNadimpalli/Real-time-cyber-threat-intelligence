import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class Settings:
    kafka_bootstrap_servers: str
    kafka_topic: str
    kafka_consumer_group: str

    postgres_host: str
    postgres_port: int
    postgres_db: str
    postgres_user: str
    postgres_password: str


settings = Settings(
    kafka_bootstrap_servers=os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"),
    kafka_topic=os.getenv("KAFKA_TOPIC", "security-events"),
    kafka_consumer_group=os.getenv(
        "KAFKA_CONSUMER_GROUP",
        "cyber-threat-consumer",
    ),
    postgres_host=os.getenv("POSTGRES_HOST", "localhost"),
    postgres_port=int(os.getenv("POSTGRES_PORT", "55432")),
    postgres_db=os.getenv("POSTGRES_DB", "cyber_threat_db"),
    postgres_user=os.getenv("POSTGRES_USER", "cyber_user"),
    postgres_password=os.getenv("POSTGRES_PASSWORD", "cyber_password"),
)