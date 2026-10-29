"""Pydantic schemas = the shape of data coming IN to and going OUT of the API.

FastAPI uses these to validate requests automatically: send a bad event and
you get a clear 422 error instead of garbage in the database.
"""
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class EventIn(BaseModel):
    timestamp: datetime
    host: str
    source: Literal["auth", "process", "network"]
    event_type: str
    user: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    bytes_sent: int | None = Field(default=None, ge=0)
    process_name: str | None = None
    process_path: str | None = None
    parent_process: str | None = None
    pid: int | None = None
    cpu_percent: float | None = Field(default=None, ge=0)
    label: str | None = None
    raw: dict | None = None


class EventOut(EventIn):
    model_config = ConfigDict(from_attributes=True)
    id: int
    ingested_at: datetime


class IngestResult(BaseModel):
    received: int
    stored: int
    dropped_blocked: int
    alerts_created: int = 0
    alerts_updated: int = 0
    incidents_created: int = 0
    incidents_updated: int = 0
    responses_executed: int = 0
    responses_pending: int = 0
