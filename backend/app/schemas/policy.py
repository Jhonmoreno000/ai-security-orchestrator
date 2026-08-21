from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field


class PolicyValidationError(Exception):
    """Excepcion lanzada cuando un plan viola las politicas de seguridad."""

    def __init__(self, message: str, violations: list["PolicyViolation"] | None = None):
        self.message = message
        self.violations = violations or []
        super().__init__(self.message)


class PolicyAction(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    WARN = "WARN"


class ScopeType(str, Enum):
    URL = "url"
    DOMAIN = "domain"
    CIDR = "cidr"
    REGEX = "regex"


class StepPolicy(BaseModel):
    """Representa un paso del plan de escaneo.

    Attributes:
        tool: Nombre de la herramienta (ej. zap, nuclei).
        operation: Operacion concreta (ej. baseline, scan_source).
        target_url: URL o path objetivo.
        timeout_seconds: Tiempo limite individual.
        parameters: Diccionario con parametros opcionales permitidos.
    """
    tool: str = Field(..., min_length=1, max_length=50, description="Nombre de la herramienta")
    operation: str = Field(..., min_length=1, max_length=50, description="Operacion concreta")
    target_url: str = Field(..., min_length=1, max_length=2048, description="URL o path objetivo")
    timeout_seconds: int = Field(default=300, ge=30, le=3600, description="Tiempo limite individual")
    parameters: dict[str, Any] = Field(default_factory=dict, description="Parametros opcionales permitidos")


class SecurityPlan(BaseModel):
    """Objeto global que agrupa la lista de steps, el target principal y la lista de scope autorizada.

    Attributes:
        steps: Lista de pasos del plan de escaneo.
        target: Target principal del escaneo.
        scope: Lista de URLs/dominios autorizados (whitelist).
    """
    steps: list[StepPolicy] = Field(..., min_length=1, description="Lista de pasos del plan de escaneo")
    target: str = Field(..., min_length=1, max_length=2048, description="Target principal del escaneo")
    scope: list[str] = Field(default_factory=list, description="Lista de URLs/dominios autorizados (whitelist)")


class ResourceLimits(BaseModel):
    """Limites de recursos configurables."""
    max_memory_mb: int = Field(default=512, ge=64, le=8192)
    max_cpu_quota: int = Field(default=50000, ge=10000, le=200000)
    max_timeout_seconds: int = Field(default=600, ge=30, le=3600)
    max_concurrent_jobs: int = Field(default=2, ge=1, le=10)
    max_concurrent_scans: int = Field(default=1, ge=1, le=5)


class PolicyViolation(BaseModel):
    """Violacion de politica detectada."""
    rule_id: str
    action: PolicyAction
    message: str
    target: str
    details: dict[str, Any] = Field(default_factory=dict)


class PolicyValidationResult(BaseModel):
    """Resultado de la validacion de politicas."""
    allowed: bool
    violations: list[PolicyViolation] = Field(default_factory=list)
    warnings: list[PolicyViolation] = Field(default_factory=list)
    applied_limits: ResourceLimits = Field(default_factory=ResourceLimits)
    metadata: dict[str, Any] = Field(default_factory=dict)
