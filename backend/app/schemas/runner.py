from datetime import datetime
from enum import Enum
from typing import Any, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class ToolType(str, Enum):
    ZAP = "zap"
    NUCLEI = "nuclei"
    SEMGREP = "semgrep"
    TRIVY = "trivy"


class ToolStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


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


class ToolInput(BaseModel):
    tool: ToolType
    target: str = Field(..., min_length=1, max_length=2048, description="URL, repo o imagen a escanear")
    options: dict[str, Any] = Field(default_factory=dict, description="Parámetros específicos del escáner")
    timeout: int = Field(default=300, ge=30, le=3600, description="Timeout en segundos")
    env_vars: dict[str, str] = Field(default_factory=dict, description="Variables de entorno adicionales")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Metadatos del contexto de escaneo")


class Artifact(BaseModel):
    artifact_id: UUID = Field(default_factory=uuid4)
    artifact_type: str = Field(..., description="Tipo de artefacto: log, report, screenshot, etc.")
    filename: str = Field(..., max_length=255)
    mime_type: str = Field(default="application/octet-stream", max_length=100)
    size_bytes: int = Field(default=0, ge=0)
    storage_path: str = Field(..., max_length=1024, description="Ruta donde se almacena el artefacto")
    checksum: Optional[str] = Field(None, max_length=128, description="SHA-256 del artefacto")
    metadata: dict[str, Any] = Field(default_factory=dict)


class FindingBase(BaseModel):
    """Modelo base para hallazgos de seguridad normalizados."""
    title: str = Field(..., min_length=1, max_length=500)
    description: Optional[str] = None
    severity: SeverityLevel
    confidence: str = Field(default="medium", max_length=50)
    cwe: Optional[str] = Field(None, max_length=50, description="CWE ID, ej: CWE-79")
    owasp: Optional[str] = Field(None, max_length=100, description="OWASP Top 10 category")
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    evidence: Optional[Any] = Field(None, description="Evidencia del hallazgo (str o dict correlacionado)")
    remediation: Optional[str] = Field(None, description="Recomendación de remediación")
    reference: Optional[str] = Field(None, description="URL de referencia")
    url: Optional[str] = Field(None, max_length=2048)
    file_path: Optional[str] = Field(None, max_length=1024)
    line_number: Optional[int] = Field(None, ge=1)
    status: FindingStatus = FindingStatus.OPEN
    fingerprint: Optional[str] = Field(None, max_length=255, description="Hash para retesting")
    scanner: ToolType
    raw_id: Optional[str] = Field(None, description="ID original del hallazgo en el escáner")
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class NormalizedFinding(FindingBase):
    """Hallazgo normalizado (extiende FindingBase)."""
    finding_id: UUID = Field(default_factory=uuid4)


class ToolResult(BaseModel):
    tool: ToolType
    status: ToolStatus
    exit_code: int = Field(default=-1, description="Código de salida del contenedor")
    duration_ms: int = Field(default=0, ge=0, description="Duración en milisegundos")
    artifacts: list[Artifact] = Field(default_factory=list, description="Artefactos generados")
    raw_log: Optional[str] = Field(None, description="Log completo de salida del escáner")
    findings: list[NormalizedFinding] = Field(default_factory=list, description="Hallazgos normalizados")
    errors: list[str] = Field(default_factory=list, description="Errores encontrados durante la ejecución")
    warnings: list[str] = Field(default_factory=list, description="Advertencias")
    metadata: dict[str, Any] = Field(default_factory=dict)
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None

    @property
    def success(self) -> bool:
        return self.status == ToolStatus.COMPLETED and self.exit_code == 0

    @property
    def findings_by_severity(self) -> dict[str, list[NormalizedFinding]]:
        result: dict[str, list[NormalizedFinding]] = {}
        for f in self.findings:
            key = f.severity.value
            if key not in result:
                result[key] = []
            result[key].append(f)
        return result

    @property
    def total_critical_high(self) -> int:
        return sum(
            1 for f in self.findings
            if f.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH)
        )


class RunnerConfig(BaseModel):
    tool: ToolType
    docker_image: str = Field(..., description="Imagen Docker del escáner")
    docker_tag: str = Field(default="latest", max_length=50)
    memory_limit: str = Field(default="512m", max_length=20)
    cpu_quota: int = Field(default=50000, ge=10000, le=100000)
    network_mode: str = Field(default="bridge", max_length=50)
    read_only: bool = Field(default=True)
    tmpfs_mounts: dict[str, str] = Field(default_factory=lambda: {"/tmp": "size=100m"})
    privileged: bool = Field(default=False)
    capabilities_drop: list[str] = Field(default_factory=lambda: ["ALL"])
    env_vars: dict[str, str] = Field(default_factory=dict)

    @property
    def full_image(self) -> str:
        return f"{self.docker_image}:{self.docker_tag}"


class ScanRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=2048)
    tools: list[ToolType] = Field(..., min_length=1, max_length=4)
    options: dict[str, Any] = Field(default_factory=dict)
    timeout: int = Field(default=300, ge=30, le=3600)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ScanResult(BaseModel):
    scan_id: UUID = Field(default_factory=uuid4)
    target: str
    status: ToolStatus
    tool_results: list[ToolResult] = Field(default_factory=list)
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    duration_ms: int = 0

    def calculate_counts(self) -> None:
        self.total_findings = sum(len(tr.findings) for tr in self.tool_results)
        for tr in self.tool_results:
            for f in tr.findings:
                if f.severity == SeverityLevel.CRITICAL:
                    self.critical_count += 1
                elif f.severity == SeverityLevel.HIGH:
                    self.high_count += 1
                elif f.severity == SeverityLevel.MEDIUM:
                    self.medium_count += 1
                elif f.severity == SeverityLevel.LOW:
                    self.low_count += 1
                elif f.severity == SeverityLevel.INFO:
                    self.info_count += 1
