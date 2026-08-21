from datetime import datetime
from enum import Enum
from typing import Any, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class WSEventType(str, Enum):
    SCAN_STARTED = "SCAN_STARTED"
    JOB_PROGRESS = "JOB_PROGRESS"
    JOB_COMPLETED = "JOB_COMPLETED"
    SCAN_FINISHED = "SCAN_FINISHED"
    ERROR = "ERROR"
    PING = "PING"
    PONG = "PONG"


class WSBaseEvent(BaseModel):
    """Evento base para mensajes WebSocket."""
    event: WSEventType
    scan_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    data: dict[str, Any] = Field(default_factory=dict)


class WSScanStarted(WSBaseEvent):
    """Notifica el inicio del orquestador."""
    event: WSEventType = WSEventType.SCAN_STARTED
    data: dict[str, Any] = Field(default_factory=lambda: {
        "target": "",
        "scanners": [],
        "message": "Scan started",
    })


class WSJobProgress(WSBaseEvent):
    """Notifica qué herramienta está corriendo."""
    event: WSEventType = WSEventType.JOB_PROGRESS
    data: dict[str, Any] = Field(default_factory=lambda: {
        "scanner": "",
        "status": "running",
        "progress_percent": 0,
        "message": "",
    })


class WSJobCompleted(WSBaseEvent):
    """Notifica el fin de una tarea individual."""
    event: WSEventType = WSEventType.JOB_COMPLETED
    data: dict[str, Any] = Field(default_factory=lambda: {
        "scanner": "",
        "status": "completed",
        "exit_code": 0,
        "findings_count": 0,
        "duration_ms": 0,
        "message": "",
    })


class WSScanFinished(WSBaseEvent):
    """Notifica la finalización con resumen global."""
    event: WSEventType = WSEventType.SCAN_FINISHED
    data: dict[str, Any] = Field(default_factory=lambda: {
        "status": "completed",
        "total_findings": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "duration_ms": 0,
        "message": "Scan finished",
    })


class WSError(WSBaseEvent):
    """Notifica un error."""
    event: WSEventType = WSEventType.ERROR
    data: dict[str, Any] = Field(default_factory=lambda: {
        "error": "",
        "scanner": None,
    })


class WSPing(WSBaseEvent):
    """Keepalive ping."""
    event: WSEventType = WSEventType.PING


class WSPong(WSBaseEvent):
    """Keepalive pong."""
    event: WSEventType = WSEventType.PONG
