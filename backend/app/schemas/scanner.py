from datetime import datetime
from enum import Enum
from typing import Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScannerType(str, Enum):
    ZAP = "zap"
    NUCLEI = "nuclei"
    SEMGREP = "semgrep"
    TRIVY = "trivy"


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ToolConfig(BaseModel):
    scanner_type: ScannerType
    target: str = Field(..., description="URL, repo o imagen a escanear")
    options: dict = Field(default_factory=dict, description="Parámetros extra del escáner")
    timeout: int = Field(default=300, ge=30, le=3600, description="Timeout en segundos")
    max_concurrency: int = Field(default=2, ge=1, le=10)


class Finding(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    title: str
    description: str
    severity: SeverityLevel
    scanner: ScannerType
    cve: Optional[str] = None
    cwe: Optional[str] = None
    url: Optional[str] = None
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    reference: Optional[str] = None
    cvss_score: Optional[float] = Field(default=None, ge=0.0, le=10.0)
    confidence: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)


class ToolResult(BaseModel):
    scanner: ScannerType
    status: ScanStatus
    findings: list[Finding] = Field(default_factory=list)
    raw_output: Optional[str] = None
    errors: list[str] = Field(default_factory=list)
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    metadata: dict = Field(default_factory=dict)


class ScanRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=2048)
    scanners: list[ScannerType] = Field(..., min_length=1, max_length=4)
    options: dict = Field(default_factory=dict)
    timeout: int = Field(default=300, ge=30, le=3600)


class ScanResponse(BaseModel):
    scan_id: UUID
    status: ScanStatus
    message: str
    created_at: datetime = Field(default_factory=datetime.utcnow)


class ScanStatusResponse(BaseModel):
    scan_id: UUID
    status: ScanStatus
    results: list[ToolResult] = Field(default_factory=list)
    progress: float = Field(default=0.0, ge=0.0, le=100.0)
