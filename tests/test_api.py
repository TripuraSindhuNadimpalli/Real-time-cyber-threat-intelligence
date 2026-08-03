from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from api.main import app


client = TestClient(app)


def make_database_connection(
    fetchone_result=None,
    fetchall_result=None,
) -> MagicMock:
    connection = MagicMock()
    cursor = MagicMock()

    connection.cursor.return_value.__enter__.return_value = cursor
    cursor.fetchone.return_value = fetchone_result
    cursor.fetchall.return_value = fetchall_result

    return connection


def test_root_endpoint() -> None:
    response = client.get("/")

    assert response.status_code == 200
    assert response.json() == {
        "message": "Cyber Threat Intelligence API is running",
        "documentation": "/docs",
    }


@patch("api.main.get_connection")
def test_health_endpoint(
    mock_get_connection: MagicMock,
) -> None:
    connection = make_database_connection(fetchone_result={"?column?": 1})
    mock_get_connection.return_value = connection

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "healthy",
        "database": "connected",
    }

    connection.close.assert_called_once()


@patch("api.main.get_connection")
def test_get_alerts(
    mock_get_connection: MagicMock,
) -> None:
    alerts = [
        {
            "id": 1,
            "alert_type": "malware_detected",
            "severity": "critical",
            "username": "emma",
            "source_ip": "203.0.113.82",
            "message": "Possible malware activity detected.",
            "event_timestamp": "2026-07-15T00:58:21.205281+00:00",
            "created_at": "2026-08-03T17:00:00+00:00",
        }
    ]

    connection = make_database_connection(fetchall_result=alerts)
    mock_get_connection.return_value = connection

    response = client.get("/alerts?limit=10")

    assert response.status_code == 200
    assert response.json() == alerts
    connection.close.assert_called_once()


def test_get_alerts_rejects_invalid_limit() -> None:
    response = client.get("/alerts?limit=0")

    assert response.status_code == 422


@patch("api.main.get_connection")
def test_get_latest_alert(
    mock_get_connection: MagicMock,
) -> None:
    alert = {
        "id": 2,
        "alert_type": "malware_detected",
        "severity": "critical",
        "username": "frank",
        "source_ip": "192.0.2.138",
        "message": "Possible malware activity detected.",
        "event_timestamp": "2026-07-15T00:58:25.748031+00:00",
        "created_at": "2026-08-03T17:01:00+00:00",
    }

    connection = make_database_connection(fetchone_result=alert)
    mock_get_connection.return_value = connection

    response = client.get("/alerts/latest")

    assert response.status_code == 200
    assert response.json() == alert
    connection.close.assert_called_once()


@patch("api.main.get_connection")
def test_get_latest_alert_returns_404(
    mock_get_connection: MagicMock,
) -> None:
    connection = make_database_connection(fetchone_result=None)
    mock_get_connection.return_value = connection

    response = client.get("/alerts/latest")

    assert response.status_code == 404
    assert response.json() == {
        "detail": "No security alerts found."
    }


@patch("api.main.get_connection")
def test_get_alert_by_id(
    mock_get_connection: MagicMock,
) -> None:
    alert = {
        "id": 5,
        "alert_type": "brute_force_attempt",
        "severity": "high",
        "username": "diana",
        "source_ip": "198.51.100.78",
        "message": "User diana had 3 failed login attempts.",
        "event_timestamp": "2026-07-15T00:58:26.251384+00:00",
        "created_at": "2026-08-03T17:02:00+00:00",
    }

    connection = make_database_connection(fetchone_result=alert)
    mock_get_connection.return_value = connection

    response = client.get("/alerts/5")

    assert response.status_code == 200
    assert response.json() == alert


@patch("api.main.get_connection")
def test_get_alert_by_id_returns_404(
    mock_get_connection: MagicMock,
) -> None:
    connection = make_database_connection(fetchone_result=None)
    mock_get_connection.return_value = connection

    response = client.get("/alerts/999")

    assert response.status_code == 404
    assert response.json() == {
        "detail": "Security alert with id 999 was not found."
    }


@patch("api.main.get_connection")
def test_get_alerts_by_severity(
    mock_get_connection: MagicMock,
) -> None:
    alerts = [
        {
            "id": 8,
            "alert_type": "malware_detected",
            "severity": "critical",
            "username": "emma",
            "source_ip": "203.0.113.82",
            "message": "Possible malware activity detected.",
            "event_timestamp": "2026-07-15T00:58:21.205281+00:00",
            "created_at": "2026-08-03T17:03:00+00:00",
        }
    ]

    connection = make_database_connection(fetchall_result=alerts)
    mock_get_connection.return_value = connection

    response = client.get("/alerts/severity/critical")

    assert response.status_code == 200
    assert response.json() == alerts


def test_get_alerts_by_severity_rejects_invalid_value() -> None:
    response = client.get("/alerts/severity/unknown")

    assert response.status_code == 400
    assert response.json() == {
        "detail": "Severity must be low, medium, high, or critical."
    }


@patch("api.main.get_connection")
def test_get_alert_statistics(
    mock_get_connection: MagicMock,
) -> None:
    statistics = {
        "total_alerts": 20,
        "critical_alerts": 8,
        "high_alerts": 6,
        "medium_alerts": 4,
        "low_alerts": 2,
    }

    connection = make_database_connection(fetchone_result=statistics)
    mock_get_connection.return_value = connection

    response = client.get("/stats")

    assert response.status_code == 200
    assert response.json() == statistics