"""Generate safe, simulated cybersecurity events for the data pipeline."""

from __future__ import annotations

import json
import random
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from faker import Faker


fake = Faker()

EVENT_TYPES = [
    "login_success",
    "login_failure",
    "file_access",
    "network_connection",
    "malware_indicator",
]

SEVERITY_BY_EVENT = {
    "login_success": "low",
    "login_failure": "medium",
    "file_access": "low",
    "network_connection": "medium",
    "malware_indicator": "high",
}

USERS = [
    "alice",
    "bob",
    "charlie",
    "diana",
    "emma",
    "frank",
    "grace",
    "henry",
]

SERVICES = [
    "ssh",
    "vpn",
    "email",
    "database",
    "web-portal",
]

DESTINATION_PORTS = [22, 53, 80, 443, 3306, 5432, 8080]


def generate_private_ip() -> str:
    """Return a simulated private IPv4 address."""
    return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def generate_public_test_ip() -> str:
    """
    Return an address from documentation-only IP ranges.

    These ranges are reserved for examples and should not represent
    real public systems.
    """
    test_ranges = [
        ("192.0.2", 1, 254),
        ("198.51.100", 1, 254),
        ("203.0.113", 1, 254),
    ]

    prefix, lower, upper = random.choice(test_ranges)
    return f"{prefix}.{random.randint(lower, upper)}"


def generate_security_event() -> dict[str, Any]:
    """Create one simulated cybersecurity event."""
    event_type = random.choice(EVENT_TYPES)

    event: dict[str, Any] = {
        "event_id": str(uuid.uuid4()),
        "event_timestamp": datetime.now(UTC).isoformat(),
        "event_type": event_type,
        "severity": SEVERITY_BY_EVENT[event_type],
        "username": random.choice(USERS),
        "source_ip": generate_public_test_ip(),
        "destination_ip": generate_private_ip(),
        "service": random.choice(SERVICES),
        "destination_port": random.choice(DESTINATION_PORTS),
        "country": fake.country_code(),
        "device_id": f"device-{random.randint(1000, 9999)}",
    }

    if event_type in {"login_success", "login_failure"}:
        event["authentication_result"] = (
            "success" if event_type == "login_success" else "failure"
        )

    if event_type == "file_access":
        event["file_path"] = random.choice(
            [
                "/finance/payroll.csv",
                "/engineering/source-code.zip",
                "/hr/employee-records.pdf",
                "/public/company-policy.pdf",
            ]
        )
        event["action"] = random.choice(["read", "write", "download"])

    if event_type == "network_connection":
        event["bytes_transferred"] = random.randint(100, 5_000_000)
        event["protocol"] = random.choice(["TCP", "UDP"])

    if event_type == "malware_indicator":
        event["indicator_type"] = random.choice(
            ["suspicious_hash", "suspicious_domain", "suspicious_process"]
        )
        event["severity"] = "high"

    return event


def write_events(number_of_events: int, delay_seconds: float) -> None:
    """Generate events, print them, and save them as JSON Lines."""
    output_path = Path("data/security_events.jsonl")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("a", encoding="utf-8") as output_file:
        for event_number in range(1, number_of_events + 1):
            event = generate_security_event()
            event_json = json.dumps(event)

            print(f"Event {event_number}: {event_json}")
            output_file.write(event_json + "\n")
            output_file.flush()

            time.sleep(delay_seconds)


if __name__ == "__main__":
    try:
        write_events(number_of_events=20, delay_seconds=0.5)
    except KeyboardInterrupt:
        print("\nEvent generation stopped by the user.")
