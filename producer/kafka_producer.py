import json
import logging
import time
from pathlib import Path
from typing import Any

from confluent_kafka import Message, Producer

from config.logging_config import setup_logging
from config.settings import settings


setup_logging()
logger = logging.getLogger(__name__)

# Locate the project root and JSONL data file
PROJECT_ROOT = Path(__file__).resolve().parent.parent
EVENTS_FILE = PROJECT_ROOT / "data" / "security_events.jsonl"


def delivery_report(error: Any, message: Message) -> None:
    """
    Handle Kafka message delivery results.
    """
    if error is not None:
        logger.error("Message delivery failed: %s", error)
        return

    logger.info(
        "Delivered | topic=%s | partition=%s | offset=%s",
        message.topic(),
        message.partition(),
        message.offset(),
    )


def create_producer() -> Producer:
    """Create and return a configured Kafka producer."""
    producer_config = {
        "bootstrap.servers": settings.kafka_bootstrap_servers,
        "client.id": "security-event-producer",
    }

    return Producer(producer_config)


def stream_events() -> None:
    """Read security events from the JSONL file and send them to Kafka."""
    if not EVENTS_FILE.exists():
        raise FileNotFoundError(
            f"Event file not found: {EVENTS_FILE}\n"
            "Run security_event_generator.py first."
        )

    producer = create_producer()
    sent_count = 0

    logger.info("Reading events from: %s", EVENTS_FILE)
    logger.info("Sending events to Kafka topic: %s", settings.kafka_topic)

    with EVENTS_FILE.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            line = line.strip()

            if not line:
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError as error:
                logger.warning(
                    "Skipping invalid JSON on line %s: %s",
                    line_number,
                    error,
                )
                continue

            event_id = event.get("event_id", str(line_number))
            event_json = json.dumps(event)

            producer.produce(
                topic=settings.kafka_topic,
                key=str(event_id),
                value=event_json,
                callback=delivery_report,
            )

            producer.poll(0)

            sent_count += 1

            logger.info(
                "Sent event %s | type=%s | severity=%s | user=%s",
                sent_count,
                event.get("event_type"),
                event.get("severity"),
                event.get("username"),
            )

            time.sleep(0.5)

    remaining_messages = producer.flush(timeout=10)

    if remaining_messages == 0:
        logger.info(
            "Successfully sent %s events.",
            sent_count,
        )
    else:
        logger.warning(
            "%s message(s) were not delivered.",
            remaining_messages,
        )


if __name__ == "__main__":
    try:
        stream_events()
    except KeyboardInterrupt:
        logger.info("Producer stopped by the user.")
    except Exception:
        logger.exception("Producer failed.")