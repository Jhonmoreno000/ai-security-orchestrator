from datetime import datetime
from enum import Enum
from typing import Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingStatus(str, Enum):
    OPEN = "OPEN"
    FIXED = "FIXED"
    STILL_PRESENT = "STILL_PRESENT"


class ScanStatus(str, Enum):
    PENDING = "PENDING"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class JobStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    RETRYING = "RETRYING"


class ScannerType(str, Enum):
    ZAP = "zap"
    NUCLEI = "nuclei"
    SEMGREP = "semgrep"
    TRIVY = "trivy"


class ReportFormat(str, Enum):
    JSON = "json"
    HTML = "html"
    PDF = "pdf"
    SARIF = "sarif"


class RetestStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    FIXED = "FIXED"
    STILL_PRESENT = "STILL_PRESENT"
    ERROR = "ERROR"


class ProjectBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    is_active: bool = True


class ProjectCreate(ProjectBase):
    pass


class ProjectUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    is_active: Optional[bool] = None


class ProjectResponse(ProjectBase):
    id: UUID
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class TargetBase(BaseModel):
    project_id: UUID
    url: str = Field(..., min_length=1, max_length=2048)
    label: Optional[str] = None
    target_type: str = Field(default="url", max_length=50)
    is_active: bool = True


class TargetCreate(TargetBase):
    pass


class TargetUpdate(BaseModel):
    url: Optional[str] = Field(None, min_length=1, max_length=2048)
    label: Optional[str] = None
    target_type: Optional[str] = None
    is_active: Optional[bool] = None


class TargetResponse(TargetBase):
    id: UUID
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class ScanBase(BaseModel):
    target_id: UUID
    project_id: UUID
    scanners: list[ScannerType] = Field(..., min_length=1)
    options: dict = Field(default_factory=dict)
    timeout: int = Field(default=300, ge=30, le=3600)


class ScanCreate(ScanBase):
    pass


class ScanUpdate(BaseModel):
    status: Optional[ScanStatus] = None
    options: Optional[dict] = None
    progress: Optional[float] = Field(None, ge=0.0, le=100.0)


class ScanResponse(ScanBase):
    id: UUID
    status: ScanStatus
    progress: float = 0.0
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class JobBase(BaseModel):
    scan_id: UUID
    scanner_type: ScannerType
    target_url: str
    config: dict = Field(default_factory=dict)
    priority: int = Field(default=0, ge=0, le=10)


class JobCreate(JobBase):
    pass


class JobUpdate(BaseModel):
    status: Optional[JobStatus] = None
    result: Optional[dict] = None
    error_message: Optional[str] = None
    retry_count: Optional[int] = None


class JobResponse(JobBase):
    id: UUID
    status: JobStatus
    result: Optional[dict] = None
    error_message: Optional[str] = None
    retry_count: int = 0
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    created_at: datetime

    class Config:
        from_attributes = True


class FindingBase(BaseModel):
    scan_id: UUID
    job_id: Optional[UUID] = None
    title: str = Field(..., min_length=1, max_length=500)
    description: Optional[str] = None
    severity: SeverityLevel
    confidence: str = Field(..., max_length=50)
    cwe: Optional[str] = Field(None, max_length=50)
    owasp: Optional[str] = Field(None, max_length=100)
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    status: FindingStatus = FindingStatus.OPEN
    fingerprint: Optional[str] = Field(None, max_length=255)
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    url: Optional[str] = Field(None, max_length=2048)
    file_path: Optional[str] = Field(None, max_length=1024)
    line_number: Optional[int] = None
    scanner: ScannerType
    reference: Optional[str] = None


class FindingCreate(FindingBase):
    pass


class FindingUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=1, max_length=500)
    description: Optional[str] = None
    severity: Optional[SeverityLevel] = None
    confidence: Optional[str] = None
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    status: Optional[FindingStatus] = None
    fingerprint: Optional[str] = None
    cvss_score: Optional[float] = None


class FindingResponse(FindingBase):
    id: UUID
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class ArtifactBase(BaseModel):
    scan_id: UUID
    finding_id: Optional[UUID] = None
    artifact_type: str = Field(..., max_length=50)
    filename: str = Field(..., max_length=255)
    mime_type: Optional[str] = Field(None, max_length=100)
    size_bytes: Optional[int] = Field(None, ge=0)
    storage_path: str = Field(..., max_length=1024)


class ArtifactCreate(ArtifactBase):
    pass


class ArtifactResponse(ArtifactBase):
    id: UUID
    created_at: datetime

    class Config:
        from_attributes = True


class ReportBase(BaseModel):
    project_id: UUID
    scan_id: Optional[UUID] = None
    title: str = Field(..., min_length=1, max_length=255)
    format: ReportFormat = ReportFormat.JSON
    is_public: bool = False


class ReportCreate(ReportBase):
    pass


class ReportResponse(ReportBase):
    id: UUID
    file_path: Optional[str] = None
    generated_at: Optional[datetime] = None
    created_at: datetime

    class Config:
        from_attributes = True


class RetestBase(BaseModel):
    finding_id: UUID
    scan_id: UUID
    status: RetestStatus = RetestStatus.PENDING
    notes: Optional[str] = None


class RetestCreate(RetestBase):
    pass


class RetestUpdate(BaseModel):
    status: Optional[RetestStatus] = None
    notes: Optional[str] = None


class RetestResponse(RetestBase):
    id: UUID
    executed_at: Optional[datetime] = None
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True
