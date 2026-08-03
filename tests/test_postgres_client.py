from unittest.mock import MagicMock, patch

import psycopg2
import pytest

from database.postgres_client import PostgresClient


def make_alert() -> dict:
    return {
        "alert_type": "malware_detected",
        "severity": "critical",
        "username": "emma",
        "source_ip": "203.0.113.82",
        "message": "Possible malware activity detected.",
        "original_event": {
            "event_timestamp": "2026-07-15T00:58:21.205281+00:00"
        },
    }


@patch("database.postgres_client.psycopg2.connect")
def test_connect_success(mock_connect: MagicMock) -> None:
    client = PostgresClient()

    client.connect(max_attempts=1)

    mock_connect.assert_called_once()
    assert client.connection is mock_connect.return_value


@patch("database.postgres_client.time.sleep")
@patch("database.postgres_client.psycopg2.connect")
def test_connect_retries_then_succeeds(
    mock_connect: MagicMock,
    mock_sleep: MagicMock,
) -> None:
    fake_connection = MagicMock()

    mock_connect.side_effect = [
        psycopg2.OperationalError("temporary failure"),
        fake_connection,
    ]

    client = PostgresClient()
    client.connect(max_attempts=2, retry_delay=0)

    assert mock_connect.call_count == 2
    assert client.connection is fake_connection
    mock_sleep.assert_called_once_with(0)


@patch("database.postgres_client.time.sleep")
@patch("database.postgres_client.psycopg2.connect")
def test_connect_raises_after_all_attempts(
    mock_connect: MagicMock,
    mock_sleep: MagicMock,
) -> None:
    mock_connect.side_effect = psycopg2.OperationalError(
        "database unavailable"
    )

    client = PostgresClient()

    with pytest.raises(psycopg2.OperationalError):
        client.connect(max_attempts=3, retry_delay=0)

    assert mock_connect.call_count == 3
    assert mock_sleep.call_count == 2


def test_save_alert_commits_transaction() -> None:
    client = PostgresClient()
    fake_connection = MagicMock()
    fake_connection.closed = False

    fake_cursor = MagicMock()
    fake_connection.cursor.return_value.__enter__.return_value = fake_cursor

    client.connection = fake_connection
    alert = make_alert()

    client.save_alert(alert, max_attempts=1)

    fake_cursor.execute.assert_called_once()
    fake_connection.commit.assert_called_once()
    fake_connection.rollback.assert_not_called()


def test_save_alert_rolls_back_on_failure() -> None:
    client = PostgresClient()
    fake_connection = MagicMock()
    fake_connection.closed = False

    fake_cursor = MagicMock()
    fake_cursor.execute.side_effect = psycopg2.OperationalError(
        "write failed"
    )
    fake_connection.cursor.return_value.__enter__.return_value = fake_cursor

    client.connection = fake_connection

    with pytest.raises(psycopg2.OperationalError):
        client.save_alert(make_alert(), max_attempts=1)

    fake_connection.rollback.assert_called_once()


def test_close_closes_connection() -> None:
    client = PostgresClient()
    fake_connection = MagicMock()

    client.connection = fake_connection
    client.close()

    fake_connection.close.assert_called_once()
    assert client.connection is None