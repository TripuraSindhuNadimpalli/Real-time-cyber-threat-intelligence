import logging
import time
from typing import Any

import psycopg2
from psycopg2.extensions import connection

from config.settings import settings


logger = logging.getLogger(__name__)


class PostgresClient:
    def __init__(self) -> None:
        self.connection: connection | None = None

    def connect(
        self,
        max_attempts: int = 5,
        retry_delay: float = 2.0,
    ) -> None:
        """Connect to PostgreSQL with limited retry handling."""
        last_error: psycopg2.Error | None = None

        for attempt in range(1, max_attempts + 1):
            try:
                self.connection = psycopg2.connect(
                    host=settings.postgres_host,
                    port=settings.postgres_port,
                    database=settings.postgres_db,
                    user=settings.postgres_user,
                    password=settings.postgres_password,
                )

                logger.info(
                    "Connected to PostgreSQL | host=%s | port=%s | "
                    "database=%s | attempt=%s",
                    settings.postgres_host,
                    settings.postgres_port,
                    settings.postgres_db,
                    attempt,
                )
                return

            except psycopg2.Error as error:
                last_error = error

                logger.warning(
                    "PostgreSQL connection attempt failed | "
                    "attempt=%s/%s | error=%s",
                    attempt,
                    max_attempts,
                    error,
                )

                if attempt < max_attempts:
                    time.sleep(retry_delay)

        logger.error(
            "Unable to connect to PostgreSQL after %s attempts.",
            max_attempts,
        )

        if last_error is not None:
            raise last_error

    def save_alert(
        self,
        alert: dict[str, Any],
        max_attempts: int = 3,
        retry_delay: float = 2.0,
    ) -> None:
        """Save a security alert with limited retry handling."""
        query = """
            INSERT INTO security_alerts (
                alert_type,
                severity,
                username,
                source_ip,
                message,
                event_timestamp
            )
            VALUES (%s, %s, %s, %s, %s, %s)
        """

        values = (
            alert.get("alert_type"),
            alert.get("severity"),
            alert.get("username"),
            alert.get("source_ip"),
            alert.get("message"),
            alert.get("original_event", {}).get("event_timestamp"),
        )

        last_error: psycopg2.Error | None = None

        for attempt in range(1, max_attempts + 1):
            try:
                if self.connection is None or self.connection.closed:
                    logger.warning(
                        "PostgreSQL connection unavailable; reconnecting."
                    )
                    self.connect(max_attempts=1)

                with self.connection.cursor() as cursor:
                    cursor.execute(query, values)

                self.connection.commit()

                logger.info(
                    "Alert saved to PostgreSQL | type=%s | severity=%s | "
                    "user=%s | source_ip=%s | attempt=%s",
                    alert.get("alert_type"),
                    alert.get("severity"),
                    alert.get("username"),
                    alert.get("source_ip"),
                    attempt,
                )
                return

            except psycopg2.Error as error:
                last_error = error

                if self.connection is not None and not self.connection.closed:
                    try:
                        self.connection.rollback()
                    except psycopg2.Error:
                        pass

                self._reset_connection()

                logger.warning(
                    "Alert save failed | attempt=%s/%s | type=%s | error=%s",
                    attempt,
                    max_attempts,
                    alert.get("alert_type"),
                    error,
                )

                if attempt < max_attempts:
                    time.sleep(retry_delay)

        logger.error(
            "Unable to save alert after %s attempts | type=%s",
            max_attempts,
            alert.get("alert_type"),
        )

        if last_error is not None:
            raise last_error

    def _reset_connection(self) -> None:
        """Close and clear an unusable PostgreSQL connection."""
        if self.connection is not None:
            try:
                self.connection.close()
            except psycopg2.Error:
                logger.warning(
                    "Failed while closing the PostgreSQL connection."
                )

        self.connection = None

    def close(self) -> None:
        """Close the PostgreSQL connection."""
        if self.connection is not None:
            self.connection.close()
            self.connection = None
            logger.info("PostgreSQL connection closed.")