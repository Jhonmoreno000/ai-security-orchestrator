from datetime import datetime
from enum import Enum
from typing import Any, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class FalsePositiveLikelihood(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class FindingAnalysisRequest(BaseModel):
    """Solicitud de analisis para un finding individual."""
    finding_id: UUID = Field(default_factory=uuid4)
    title: str = Field(..., min_length=1, max_length=500)
    evidence: Optional[str] = None
    cwe: Optional[str] = Field(None, max_length=50)
    endpoint: Optional[str] = Field(None, max_length=2048)
    severity: Optional[str] = Field(None, max_length=20)
    scanner: Optional[str] = Field(None, max_length=50)
    tech_stack: list[str] = Field(default_factory=list, description="Stack tecnologico detectado por ProjectAnalyzer")


class FindingAnalysisResult(BaseModel):
    """Resultado del analisis IA de un finding."""
    finding_id: UUID = Field(default_factory=uuid4)
    summary: str = Field(default="", description="Resumen ejecutivo del problema en 2-3 oraciones")
    business_impact: str = Field(default="", description="Explicacion clara del riesgo real si se explota la falla")
    remediation_steps: list[str] = Field(default_factory=list, description="Pasos tecnicos concretos para corregirlo")
    code_example: Optional[str] = Field(None, description="Fragmento de codigo o configuracion de ejemplo en la tecnologia del proyecto")
    false_positive_likelihood: FalsePositiveLikelihood = Field(default=FalsePositiveLikelihood.LOW)
    false_positive_reasoning: str = Field(default="")
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)
