import logging
from datetime import datetime
from typing import Any

import psycopg2
from fastapi import FastAPI, HTTPException, Query
from psycopg2.extensions import connection
from psycopg2.extras import RealDictCursor
from pydantic import BaseModel, ConfigDict

from config.logging_config import setup_logging
from config.settings import settings


setup_logging()
logger = logging.getLogger(__name__)


# -----------------------------
# Pydantic response models
# -----------------------------
class AlertResponse(BaseModel):
    id: int
    alert_type: str
    severity: str
    username: str | None
    source_ip: str | None
    message: str
    event_timestamp: str | datetime | None
    created_at: str | datetime

    model_config = ConfigDict(from_attributes=True)


class HealthResponse(BaseModel):
    status: str
    database: str


class RootResponse(BaseModel):
    message: str
    documentation: str


class AlertStatisticsResponse(BaseModel):
    total_alerts: int
    critical_alerts: int
    high_alerts: int
    medium_alerts: int
    low_alerts: int


# -----------------------------
# FastAPI application
# -----------------------------
app = FastAPI(
    title="Cyber Threat Intelligence API",
    description="REST API for detected cybersecurity alerts.",
    version="1.0.0",
)


def get_connection() -> connection:
    """Create and return a PostgreSQL connection for the API."""
    try:
        return psycopg2.connect(
            host=settings.postgres_host,
            port=settings.postgres_port,
            database=settings.postgres_db,
            user=settings.postgres_user,
            password=settings.postgres_password,
            cursor_factory=RealDictCursor,
        )

    except psycopg2.Error as error:
        logger.exception("API failed to connect to PostgreSQL.")

        raise HTTPException(
            status_code=503,
            detail="Database service is currently unavailable.",
        ) from error


@app.get("/", response_model=RootResponse)
def root() -> dict[str, str]:
    return {
        "message": "Cyber Threat Intelligence API is running",
        "documentation": "/docs",
    }


@app.get("/health", response_model=HealthResponse)
def health_check() -> dict[str, str]:
    """Check whether the API and PostgreSQL are available."""
    database_connection = get_connection()

    try:
        with database_connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()

        return {
            "status": "healthy",
            "database": "connected",
        }

    except psycopg2.Error as error:
        logger.exception("Database health check failed.")

        raise HTTPException(
            status_code=503,
            detail="Database health check failed.",
        ) from error

    finally:
        database_connection.close()


@app.get("/alerts", response_model=list[AlertResponse])
def get_alerts(
    limit: int = Query(
        default=100,
        ge=1,
        le=500,
        description="Maximum number of alerts to return.",
    ),
    offset: int = Query(
        default=0,
        ge=0,
        description="Number of alerts to skip.",
    ),
    severity: str | None = Query(
        default=None,
        description="Filter by severity: low, medium, high, or critical.",
    ),
    username: str | None = Query(
        default=None,
        min_length=1,
        description="Filter by username.",
    ),
    source_ip: str | None = Query(
        default=None,
        min_length=1,
        description="Filter by source IP address.",
    ),
) -> list[dict[str, Any]]:
    """Retrieve alerts with optional filtering and pagination."""
    allowed_severities = {"low", "medium", "high", "critical"}
    normalized_severity: str | None = None

    if severity is not None:
        normalized_severity = severity.lower()

        if normalized_severity not in allowed_severities:
            raise HTTPException(
                status_code=400,
                detail="Severity must be low, medium, high, or critical.",
            )

    database_connection = get_connection()

    try:
        conditions: list[str] = []
        parameters: list[Any] = []

        if normalized_severity is not None:
            conditions.append("severity = %s")
            parameters.append(normalized_severity)

        if username is not None:
            conditions.append("username = %s")
            parameters.append(username)

        if source_ip is not None:
            conditions.append("source_ip = %s")
            parameters.append(source_ip)

        where_clause = ""

        if conditions:
            where_clause = "WHERE " + " AND ".join(conditions)

        query = f"""
            SELECT
                id,
                alert_type,
                severity,
                username,
                source_ip,
                message,
                event_timestamp,
                created_at
            FROM security_alerts
            {where_clause}
            ORDER BY created_at DESC
            LIMIT %s
            OFFSET %s
        """

        parameters.extend([limit, offset])

        with database_connection.cursor() as cursor:
            cursor.execute(query, tuple(parameters))
            alerts = cursor.fetchall()

        logger.info(
            "Returned %s alerts | limit=%s | offset=%s | "
            "severity=%s | username=%s | source_ip=%s",
            len(alerts),
            limit,
            offset,
            normalized_severity,
            username,
            source_ip,
        )

        return alerts

    except psycopg2.Error as error:
        logger.exception("Failed to retrieve alerts.")

        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve security alerts.",
        ) from error

    finally:
        database_connection.close()


@app.get("/alerts/latest", response_model=AlertResponse)
def get_latest_alert() -> dict[str, Any]:
    """Retrieve the most recently created security alert."""
    database_connection = get_connection()

    try:
        with database_connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    id,
                    alert_type,
                    severity,
                    username,
                    source_ip,
                    message,
                    event_timestamp,
                    created_at
                FROM security_alerts
                ORDER BY created_at DESC
                LIMIT 1
                """
            )

            alert = cursor.fetchone()

        if alert is None:
            raise HTTPException(
                status_code=404,
                detail="No security alerts found.",
            )

        return alert

    except HTTPException:
        raise

    except psycopg2.Error as error:
        logger.exception("Failed to retrieve the latest alert.")

        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve the latest security alert.",
        ) from error

    finally:
        database_connection.close()


# This route must appear before /alerts/{alert_id}.
@app.get(
    "/alerts/severity/{severity}",
    response_model=list[AlertResponse],
)
def get_alerts_by_severity(
    severity: str,
) -> list[dict[str, Any]]:
    """Retrieve alerts matching a particular severity."""
    allowed_severities = {"low", "medium", "high", "critical"}
    normalized_severity = severity.lower()

    if normalized_severity not in allowed_severities:
        raise HTTPException(
            status_code=400,
            detail="Severity must be low, medium, high, or critical.",
        )

    database_connection = get_connection()

    try:
        with database_connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    id,
                    alert_type,
                    severity,
                    username,
                    source_ip,
                    message,
                    event_timestamp,
                    created_at
                FROM security_alerts
                WHERE severity = %s
                ORDER BY created_at DESC
                """,
                (normalized_severity,),
            )

            alerts = cursor.fetchall()

        return alerts

    except psycopg2.Error as error:
        logger.exception(
            "Failed to retrieve alerts with severity=%s.",
            normalized_severity,
        )

        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve alerts by severity.",
        ) from error

    finally:
        database_connection.close()


@app.get("/alerts/{alert_id}", response_model=AlertResponse)
def get_alert_by_id(alert_id: int) -> dict[str, Any]:
    """Retrieve a security alert by its database ID."""
    database_connection = get_connection()

    try:
        with database_connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    id,
                    alert_type,
                    severity,
                    username,
                    source_ip,
                    message,
                    event_timestamp,
                    created_at
                FROM security_alerts
                WHERE id = %s
                """,
                (alert_id,),
            )

            alert = cursor.fetchone()

        if alert is None:
            raise HTTPException(
                status_code=404,
                detail=f"Security alert with id {alert_id} was not found.",
            )

        return alert

    except HTTPException:
        raise

    except psycopg2.Error as error:
        logger.exception(
            "Failed to retrieve alert with id=%s.",
            alert_id,
        )

        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve the security alert.",
        ) from error

    finally:
        database_connection.close()


@app.get("/stats", response_model=AlertStatisticsResponse)
def get_alert_statistics() -> dict[str, Any]:
    """Return alert counts grouped by severity."""
    database_connection = get_connection()

    try:
        with database_connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    COUNT(*) AS total_alerts,
                    COUNT(*) FILTER (
                        WHERE severity = 'critical'
                    ) AS critical_alerts,
                    COUNT(*) FILTER (
                        WHERE severity = 'high'
                    ) AS high_alerts,
                    COUNT(*) FILTER (
                        WHERE severity = 'medium'
                    ) AS medium_alerts,
                    COUNT(*) FILTER (
                        WHERE severity = 'low'
                    ) AS low_alerts
                FROM security_alerts
                """
            )

            statistics = cursor.fetchone()

        return statistics

    except psycopg2.Error as error:
        logger.exception("Failed to retrieve alert statistics.")

        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve alert statistics.",
        ) from error

    finally:
        database_connection.close()