import json
import logging
import time
import uuid
from datetime import datetime, timezone

from confluent_kafka import Producer

from config.logging_config import setup_logging
from config.settings import settings


setup_logging()
logger = logging.getLogger(__name__)


def delivery_report(error, message) -> None:
    if error is not None:
        logger.error("Delivery failed: %s", error)
        return

    logger.info(
        "Delivered test event | topic=%s | partition=%s | offset=%s",
        message.topic(),
        message.partition(),
        message.offset(),
    )


def main() -> None:
    producer = Producer(
        {
            "bootstrap.servers": settings.kafka_bootstrap_servers,
            "client.id": "retry-test-producer",
        }
    )

    event = {
        "event_id": str(uuid.uuid4()),
        "event_timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "malware_indicator",
        "severity": "high",
        "username": "retry_test_user",
        "source_ip": "203.0.113.250",
        "destination_ip": "10.0.0.50",
        "service": "test-service",
        "destination_port": 443,
        "country": "US",
        "device_id": "retry-test-device",
        "indicator_type": "suspicious_hash",
    }

    logger.info(
        "Waiting 10 seconds before sending the malware test event."
    )
    time.sleep(10)

    producer.produce(
        topic=settings.kafka_topic,
        key=event["event_id"],
        value=json.dumps(event),
        callback=delivery_report,
    )

    producer.flush()
    logger.info("Retry test event sent.")


if __name__ == "__main__":
    main()