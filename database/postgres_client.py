import os
from typing import Any

import psycopg2
from psycopg2.extensions import connection


class PostgresClient:
    def __init__(self) -> None:
        self.connection: connection | None = None

    def connect(self) -> None:
        self.connection = psycopg2.connect(
            host=os.getenv("POSTGRES_HOST", "localhost"),
            port=os.getenv("POSTGRES_PORT", "55432"),
            database=os.getenv("POSTGRES_DB", "cyber_threat_db"),
            user=os.getenv("POSTGRES_USER", "cyber_user"),
            password=os.getenv("POSTGRES_PASSWORD", "cyber_password"),
        )

        print("Connected to PostgreSQL")

    def save_alert(self, alert: dict[str, Any]) -> None:
        if self.connection is None:
            raise RuntimeError("PostgreSQL connection has not been established.")

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
            alert.get("timestamp"),
        )

        try:
            with self.connection.cursor() as cursor:
                cursor.execute(query, values)

            self.connection.commit()
            print("Alert saved to PostgreSQL")

        except Exception:
            self.connection.rollback()
            raise

    def close(self) -> None:
        if self.connection is not None:
            self.connection.close()
            print("PostgreSQL connection closed")