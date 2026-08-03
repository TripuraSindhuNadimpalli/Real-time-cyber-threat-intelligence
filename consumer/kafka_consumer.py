import json
import logging

from confluent_kafka import Consumer, KafkaError

from config.logging_config import setup_logging
from config.settings import settings
from database.postgres_client import PostgresClient
from detection.threat_detector import ThreatDetector


setup_logging()
logger = logging.getLogger(__name__)


def create_consumer() -> Consumer:
    """Create and return a configured Kafka consumer."""
    consumer_config = {
        "bootstrap.servers": settings.kafka_bootstrap_servers,
        "group.id": settings.kafka_consumer_group,
        "auto.offset.reset": "earliest",
        "enable.auto.commit": False,
    }

    return Consumer(consumer_config)


def consume_events() -> None:
    """Read events from Kafka, detect threats, and save alerts."""
    detector = ThreatDetector()
    database = PostgresClient()
    consumer = create_consumer()

    try:
        database.connect()
        consumer.subscribe([settings.kafka_topic])

        logger.info(
            "Listening for events on topic: %s",
            settings.kafka_topic,
        )
        logger.info("Press Control + C to stop.")

        while True:
            message = consumer.poll(timeout=1.0)

            if message is None:
                continue

            if message.error():
                if message.error().code() == KafkaError._PARTITION_EOF:
                    continue

                logger.error(
                    "Kafka consumer error: %s",
                    message.error(),
                )
                continue

            try:
                event = json.loads(
                    message.value().decode("utf-8")
                )
            except (json.JSONDecodeError, UnicodeDecodeError) as error:
                logger.warning(
                    "Invalid message at offset=%s: %s",
                    message.offset(),
                    error,
                )

                consumer.commit(
                    message=message,
                    asynchronous=False,
                )
                continue

            try:
                logger.info(
                    "Received offset=%s | type=%s | severity=%s | "
                    "user=%s | source_ip=%s",
                    message.offset(),
                    event.get("event_type"),
                    event.get("severity"),
                    event.get("username"),
                    event.get("source_ip"),
                )

                alerts = detector.analyze(event)

                for alert in alerts:
                    logger.warning(
                        "SECURITY ALERT | type=%s | severity=%s | "
                        "user=%s | source_ip=%s | message=%s",
                        alert.get("alert_type"),
                        alert.get("severity"),
                        alert.get("username"),
                        alert.get("source_ip"),
                        alert.get("message"),
                    )

                    database.save_alert(alert)

                consumer.commit(
                    message=message,
                    asynchronous=False,
                )

            except Exception:
                logger.exception(
                    "Failed to process message at offset=%s. "
                    "Offset was not committed.",
                    message.offset(),
                )

    except KeyboardInterrupt:
        logger.info("Consumer stopped by the user.")

    finally:
        consumer.close()
        logger.info("Kafka consumer closed safely.")
        database.close()


if __name__ == "__main__":
    consume_events()