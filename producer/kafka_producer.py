import json
import time
from pathlib import Path

from confluent_kafka import Producer


# Kafka configuration
KAFKA_BOOTSTRAP_SERVERS = "localhost:9092"
KAFKA_TOPIC = "security-events"

# Locate the project root and JSONL data file
PROJECT_ROOT = Path(__file__).resolve().parent.parent
EVENTS_FILE = PROJECT_ROOT / "data" / "security_events.jsonl"


def delivery_report(error, message):
    """
    Called by Kafka after it attempts to deliver a message.

    If delivery fails, it prints the error.
    If delivery succeeds, it prints the topic, partition, and offset.
    """
    if error is not None:
        print(f"Message delivery failed: {error}")
    else:
        print(
            f"Delivered to topic={message.topic()}, "
            f"partition={message.partition()}, "
            f"offset={message.offset()}"
        )


def create_producer():
    """Create and return a configured Kafka producer."""
    config = {
        "bootstrap.servers": KAFKA_BOOTSTRAP_SERVERS,
        "client.id": "security-event-producer",
    }

    return Producer(config)


def stream_events():
    """Read security events from the JSONL file and send them to Kafka."""
    if not EVENTS_FILE.exists():
        raise FileNotFoundError(
            f"Event file not found: {EVENTS_FILE}\n"
            "Run security_event_generator.py first."
        )

    producer = create_producer()
    sent_count = 0

    print(f"Reading events from: {EVENTS_FILE}")
    print(f"Sending events to Kafka topic: {KAFKA_TOPIC}\n")

    with EVENTS_FILE.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            line = line.strip()

            if not line:
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError as error:
                print(f"Skipping invalid JSON on line {line_number}: {error}")
                continue

            event_id = event.get("event_id", str(line_number))
            event_json = json.dumps(event)

            producer.produce(
                topic=KAFKA_TOPIC,
                key=str(event_id),
                value=event_json,
                callback=delivery_report,
            )

            producer.poll(0)

            sent_count += 1

            print(
                f"Sent event {sent_count}: "
                f"{event.get('event_type', 'unknown')}"
            )

            # Simulates events arriving over time
            time.sleep(0.5)

    # Wait until all queued messages have been delivered
    remaining_messages = producer.flush(timeout=10)

    if remaining_messages == 0:
        print(f"\nSuccessfully sent {sent_count} events.")
    else:
        print(
            f"\nWarning: {remaining_messages} message(s) "
            "were not delivered."
        )


if __name__ == "__main__":
    try:
        stream_events()
    except KeyboardInterrupt:
        print("\nProducer stopped by the user.")
    except Exception as error:
        print(f"\nProducer error: {error}")