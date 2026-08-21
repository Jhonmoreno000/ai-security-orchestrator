from datetime import datetime
from enum import Enum
from typing import Any, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class AIProviderType(str, Enum):
    OLLAMA = "ollama"
    OPENAI = "openai"
    GEMINI = "gemini"


class PrivacyMode(str, Enum):
    LOCAL = "local"
    SANITIZED = "sanitized"
    FULL_CLOUD = "full_cloud"


class PlanRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=2048)
    scan_type: str = Field(..., max_length=50)
    context: dict[str, Any] = Field(default_factory=dict)
    previous_findings: list[dict[str, Any]] = Field(default_factory=list)
    constraints: dict[str, Any] = Field(default_factory=dict)


class PlanResponse(BaseModel):
    plan_id: UUID = Field(default_factory=uuid4)
    tools: list[dict[str, Any]] = Field(default_factory=list)
    strategy: str = Field(default="", max_length=500)
    estimated_duration_seconds: int = Field(default=300)
    reasoning: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class EvidenceAnalysisRequest(BaseModel):
    findings: list[dict[str, Any]] = Field(..., min_length=1)
    target_info: dict[str, Any] = Field(default_factory=dict)
    scan_context: dict[str, Any] = Field(default_factory=dict)


class EvidenceAnalysisResponse(BaseModel):
    analysis_id: UUID = Field(default_factory=uuid4)
    summary: str = Field(default="")
    risk_score: float = Field(default=0.0, ge=0.0, le=10.0)
    critical_paths: list[str] = Field(default_factory=list)
    attack_vectors: list[dict[str, Any]] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    metadata: dict[str, Any] = Field(default_factory=dict)


class FindingExplanationRequest(BaseModel):
    finding: dict[str, Any]
    include_remediation: bool = True
    detail_level: str = Field(default="medium", max_length=20)


class FindingExplanationResponse(BaseModel):
    explanation_id: UUID = Field(default_factory=uuid4)
    title: str = Field(default="")
    explanation: str = Field(default="")
    impact: str = Field(default="")
    remediation: Optional[str] = None
    references: list[str] = Field(default_factory=list)
    cvss_breakdown: Optional[dict[str, Any]] = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class RemediationRequest(BaseModel):
    finding: dict[str, Any]
    code_context: Optional[str] = None
    tech_stack: list[str] = Field(default_factory=list)
    priority: str = Field(default="medium", max_length=20)


class RemediationResponse(BaseModel):
    remediation_id: UUID = Field(default_factory=uuid4)
    short_fix: str = Field(default="")
    detailed_steps: list[str] = Field(default_factory=list)
    code_example: Optional[str] = None
    references: list[str] = Field(default_factory=list)
    estimated_effort: str = Field(default="unknown")
    metadata: dict[str, Any] = Field(default_factory=dict)


class SanitizationResult(BaseModel):
    original: str
    sanitized: str
    masks_count: int = 0
    patterns_matched: list[str] = Field(default_factory=list)


class AIProviderConfig(BaseModel):
    provider_type: AIProviderType = AIProviderType.OLLAMA
    base_url: str = Field(default="http://localhost:11434")
    model: str = Field(default="codellama")
    api_key: Optional[str] = None
    timeout: int = Field(default=120, ge=10, le=600)
    max_tokens: int = Field(default=4096, ge=256, le=32768)
    temperature: float = Field(default=0.3, ge=0.0, le=2.0)
    privacy_mode: PrivacyMode = PrivacyMode.LOCAL
    enabled: bool = True
