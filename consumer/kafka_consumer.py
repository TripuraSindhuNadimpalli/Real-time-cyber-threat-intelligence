import json

from confluent_kafka import Consumer, KafkaError


KAFKA_BOOTSTRAP_SERVERS = "localhost:9092"
KAFKA_TOPIC = "security-events"
CONSUMER_GROUP = "security-event-consumer-group"


def create_consumer():
    """Create and return a configured Kafka consumer."""
    config = {
        "bootstrap.servers": KAFKA_BOOTSTRAP_SERVERS,
        "group.id": CONSUMER_GROUP,
        "auto.offset.reset": "earliest",
    }

    return Consumer(config)


def consume_events():
    """Read and display security events from Kafka."""
    consumer = create_consumer()
    consumer.subscribe([KAFKA_TOPIC])

    print(f"Listening for events on topic: {KAFKA_TOPIC}")
    print("Press Control + C to stop.\n")

    try:
        while True:
            message = consumer.poll(timeout=1.0)

            if message is None:
                continue

            if message.error():
                if message.error().code() == KafkaError._PARTITION_EOF:
                    continue

                print(f"Kafka consumer error: {message.error()}")
                continue

            try:
                event = json.loads(message.value().decode("utf-8"))
            except json.JSONDecodeError as error:
                print(f"Invalid JSON message: {error}")
                continue

            print(
                f"Received offset={message.offset()} | "
                f"type={event.get('event_type')} | "
                f"severity={event.get('severity')} | "
                f"user={event.get('username')} | "
                f"source_ip={event.get('source_ip')}"
            )

    except KeyboardInterrupt:
        print("\nConsumer stopped by the user.")

    finally:
        consumer.close()
        print("Kafka consumer closed safely.")


if __name__ == "__main__":
    consume_events()