from collections import defaultdict
from typing import Any


class ThreatDetector:
    """Detect suspicious activity in cybersecurity events."""

    def __init__(self, failed_login_threshold: int = 3) -> None:
        self.failed_login_threshold = failed_login_threshold
        self.failed_login_counts: dict[str, int] = defaultdict(int)

    def analyze(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        """Analyze one event and return any generated security alerts."""
        alerts: list[dict[str, Any]] = []

        event_type = event.get("event_type")
        severity = event.get("severity")
        username = event.get("username", "unknown")
        source_ip = event.get("source_ip", "unknown")

        if event_type == "malware_indicator":
            alerts.append(
                self._create_alert(
                    alert_type="malware_detected",
                    severity="critical",
                    message=f"Possible malware activity detected for user {username}.",
                    event=event,
                )
            )

        if event_type == "login_failure":
            self.failed_login_counts[username] += 1
            failure_count = self.failed_login_counts[username]

            if failure_count >= self.failed_login_threshold:
                alerts.append(
                    self._create_alert(
                        alert_type="brute_force_attempt",
                        severity="high",
                        message=(
                            f"User {username} had {failure_count} failed login "
                            f"attempts. Latest source IP: {source_ip}."
                        ),
                        event=event,
                    )
                )

        elif event_type == "login_success":
            self.failed_login_counts[username] = 0

        if severity == "high" and event_type != "malware_indicator":
            alerts.append(
                self._create_alert(
                    alert_type="high_severity_activity",
                    severity="high",
                    message=f"High-severity activity detected for user {username}.",
                    event=event,
                )
            )

        return alerts

    @staticmethod
    def _create_alert(
        alert_type: str,
        severity: str,
        message: str,
        event: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "alert_type": alert_type,
            "severity": severity,
            "message": message,
            "username": event.get("username"),
            "source_ip": event.get("source_ip"),
            "original_event": event,
        }