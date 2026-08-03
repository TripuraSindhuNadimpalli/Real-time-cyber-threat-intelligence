from datetime import datetime

from pydantic import BaseModel, ConfigDict


class AlertResponse(BaseModel):
    id: int
    alert_type: str
    severity: str
    username: str | None
    source_ip: str | None
    message: str
    event_timestamp: datetime | None
    created_at: datetime

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