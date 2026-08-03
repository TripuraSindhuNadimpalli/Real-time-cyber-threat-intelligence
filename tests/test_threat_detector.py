from detection.threat_detector import ThreatDetector


def test_malware_indicator_generates_critical_alert() -> None:
    detector = ThreatDetector()

    event = {
        "event_type": "malware_indicator",
        "severity": "high",
        "username": "emma",
        "source_ip": "203.0.113.82",
    }

    alerts = detector.analyze(event)

    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "malware_detected"
    assert alerts[0]["severity"] == "critical"
    assert alerts[0]["username"] == "emma"
    assert alerts[0]["source_ip"] == "203.0.113.82"
    assert alerts[0]["original_event"] == event


def test_login_failure_below_threshold_generates_no_alert() -> None:
    detector = ThreatDetector(failed_login_threshold=3)

    event = {
        "event_type": "login_failure",
        "severity": "medium",
        "username": "bob",
        "source_ip": "192.0.2.10",
    }

    first_alerts = detector.analyze(event)
    second_alerts = detector.analyze(event)

    assert first_alerts == []
    assert second_alerts == []


def test_login_failure_at_threshold_generates_brute_force_alert() -> None:
    detector = ThreatDetector(failed_login_threshold=3)

    event = {
        "event_type": "login_failure",
        "severity": "medium",
        "username": "diana",
        "source_ip": "198.51.100.20",
    }

    detector.analyze(event)
    detector.analyze(event)
    alerts = detector.analyze(event)

    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "brute_force_attempt"
    assert alerts[0]["severity"] == "high"
    assert alerts[0]["username"] == "diana"
    assert "3 failed login attempts" in alerts[0]["message"]


def test_login_success_resets_failed_login_count() -> None:
    detector = ThreatDetector(failed_login_threshold=3)

    failure_event = {
        "event_type": "login_failure",
        "severity": "medium",
        "username": "alice",
        "source_ip": "192.0.2.30",
    }

    success_event = {
        "event_type": "login_success",
        "severity": "low",
        "username": "alice",
        "source_ip": "192.0.2.30",
    }

    detector.analyze(failure_event)
    detector.analyze(failure_event)
    detector.analyze(success_event)

    alerts = detector.analyze(failure_event)

    assert alerts == []


def test_high_severity_non_malware_event_generates_alert() -> None:
    detector = ThreatDetector()

    event = {
        "event_type": "network_connection",
        "severity": "high",
        "username": "frank",
        "source_ip": "203.0.113.40",
    }

    alerts = detector.analyze(event)

    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "high_severity_activity"
    assert alerts[0]["severity"] == "high"


def test_normal_event_generates_no_alert() -> None:
    detector = ThreatDetector()

    event = {
        "event_type": "file_access",
        "severity": "low",
        "username": "charlie",
        "source_ip": "198.51.100.50",
    }

    alerts = detector.analyze(event)

    assert alerts == []


def test_failed_login_counts_are_separate_for_each_user() -> None:
    detector = ThreatDetector(failed_login_threshold=3)

    alice_event = {
        "event_type": "login_failure",
        "severity": "medium",
        "username": "alice",
        "source_ip": "192.0.2.60",
    }

    bob_event = {
        "event_type": "login_failure",
        "severity": "medium",
        "username": "bob",
        "source_ip": "192.0.2.61",
    }

    detector.analyze(alice_event)
    detector.analyze(alice_event)
    detector.analyze(bob_event)

    alice_alerts = detector.analyze(alice_event)

    assert len(alice_alerts) == 1
    assert alice_alerts[0]["username"] == "alice"