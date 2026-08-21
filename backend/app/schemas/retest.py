from datetime import datetime
from enum import Enum
from typing import Any, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class RetestStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    FIXED = "FIXED"
    STILL_PRESENT = "STILL_PRESENT"
    INCONCLUSIVE = "INCONCLUSIVE"
    ERROR = "ERROR"


class RetestRequest(BaseModel):
    """Solicitud de retest para un finding."""
    finding_id: UUID
    fingerprint: str = Field(..., min_length=1, max_length=255)
    source_tool: str = Field(..., max_length=50)
    endpoint: str = Field(..., min_length=1, max_length=2048)
    scan_id: UUID


class RetestResult(BaseModel):
    """Resultado de un retest."""
    retest_id: UUID = Field(default_factory=uuid4)
    finding_id: UUID
    previous_status: str
    new_status: RetestStatus
    fingerprints_before: list[str] = Field(default_factory=list)
    fingerprints_after: list[str] = Field(default_factory=list)
    notes: str = Field(default="")
    duration_ms: int = Field(default=0)
    errors: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class RetestBatchRequest(BaseModel):
    """Solicitud de retest para multiples findings."""
    scan_id: UUID
    finding_ids: list[UUID] = Field(..., min_length=1)


class RetestBatchResult(BaseModel):
    """Resultado de un retest en lote."""
    total: int = Field(default=0)
    fixed: int = Field(default=0)
    still_present: int = Field(default=0)
    inconclusive: int = Field(default=0)
    errors: int = Field(default=0)
    results: list[RetestResult] = Field(default_factory=list)
