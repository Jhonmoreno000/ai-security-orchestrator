from datetime import datetime
from enum import Enum
from typing import Any, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class ImpactLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NEGLIGIBLE = "NEGLIGIBLE"


class CIAImpact(BaseModel):
    """Impacto en la triada CIA (Confidencialidad, Integridad, Disponibilidad)."""
    confidentiality: ImpactLevel = Field(default=ImpactLevel.NEGLIGIBLE)
    integrity: ImpactLevel = Field(default=ImpactLevel.NEGLIGIBLE)
    availability: ImpactLevel = Field(default=ImpactLevel.NEGLIGIBLE)
    explanation: str = Field(default="", description="Explicacion del impacto CIA")


class FalsePositiveAssessment(BaseModel):
    """Evaluacion de probabilidad de falso positivo."""
    is_likely_false_positive: bool = Field(default=False)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    reasoning: str = Field(default="")
    indicators: list[str] = Field(default_factory=list)


class FindingEnrichment(BaseModel):
    """Resultado del enriquecimiento de un finding por AI Analyst."""
    finding_id: UUID = Field(default_factory=uuid4)
    technical_explanation: str = Field(default="", description="Explicacion tecnica clara y sin jerga")
    cia_impact: CIAImpact = Field(default_factory=CIAImpact)
    business_impact: str = Field(default="", description="Evaluacion de impacto de negocio")
    remediation_code: Optional[str] = Field(None, description="Codigo de remediacion especifico")
    remediation_steps: list[str] = Field(default_factory=list, description="Pasos concretos de remediacion")
    false_positive_assessment: FalsePositiveAssessment = Field(default_factory=FalsePositiveAssessment)
    enriched_evidence: Optional[Any] = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class AnalysisRequest(BaseModel):
    """Solicitud de analisis para un lote de findings."""
    findings: list[dict[str, Any]] = Field(..., min_length=1)
    tech_stack: list[str] = Field(default_factory=list, description="Stack tecnologico detectado por ProjectAnalyzer")
    project_context: dict[str, Any] = Field(default_factory=dict)
    detail_level: str = Field(default="medium", max_length=20)


class AnalysisResponse(BaseModel):
    """Respuesta del analisis con enrichments para cada finding."""
    analysis_id: UUID = Field(default_factory=uuid4)
    enrichments: list[FindingEnrichment] = Field(default_factory=list)
    summary: str = Field(default="")
    total_analyzed: int = Field(default=0)
    false_positives_detected: int = Field(default=0)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)
