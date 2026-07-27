import json
import time

from confluent_kafka import Producer


KAFKA_BOOTSTRAP_SERVERS = "localhost:9092"
KAFKA_TOPIC = "security-events"


def delivery_report(error, message):
    if error is not None:
        print(f"Delivery failed: {error}")
        return

    print(
        f"Delivered to topic={message.topic()}, "
        f"partition={message.partition()}, "
        f"offset={message.offset()}"
    )


def main():
    producer = Producer(
        {
            "bootstrap.servers": KAFKA_BOOTSTRAP_SERVERS,
        }
    )

    test_events = [
        {
            "event_type": "login_failure",
            "severity": "medium",
            "username": "test_user",
            "source_ip": "203.0.113.200",
        },
        {
            "event_type": "login_failure",
            "severity": "medium",
            "username": "test_user",
            "source_ip": "203.0.113.200",
        },
        {
            "event_type": "login_failure",
            "severity": "medium",
            "username": "test_user",
            "source_ip": "203.0.113.200",
        },
    ]

    for number, event in enumerate(test_events, start=1):
        producer.produce(
            KAFKA_TOPIC,
            value=json.dumps(event).encode("utf-8"),
            callback=delivery_report,
        )

        producer.poll(0)
        print(f"Sent failed-login event {number}")
        time.sleep(1)

    producer.flush()
    print("Brute-force test events sent successfully.")


if __name__ == "__main__":
    main()