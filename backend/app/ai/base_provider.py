from abc import ABC, abstractmethod
from typing import Any

import structlog

from app.schemas.ai import (
    AIProviderConfig,
    EvidenceAnalysisRequest,
    EvidenceAnalysisResponse,
    FindingExplanationRequest,
    FindingExplanationResponse,
    PlanRequest,
    PlanResponse,
    RemediationRequest,
    RemediationResponse,
)

logger = structlog.get_logger()


class BaseAIProvider(ABC):
    """Clase abstracta base para proveedores de IA.

    Cada proveedor concreto debe implementar:
    - generate_plan(): Genera plan de escaneo
    - analyze_evidence(): Analiza evidencia de hallazgos
    - explain_finding(): Explica un hallazgo específico
    - suggest_remediation(): Sugiere remediación
    - health_check(): Verifica conectividad con el proveedor
    """

    def __init__(self, config: AIProviderConfig):
        self.config = config
        self._is_healthy = False

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Retorna el nombre del proveedor."""
        ...

    @abstractmethod
    async def generate_plan(self, request: PlanRequest) -> PlanResponse:
        """Genera un plan de escaneo optimizado.

        Args:
            request: Solicitud con contexto del objetivo.

        Returns:
            PlanResponse con los pasos a ejecutar.
        """
        ...

    @abstractmethod
    async def analyze_evidence(
        self, request: EvidenceAnalysisRequest
    ) -> EvidenceAnalysisResponse:
        """Analiza evidencia recolectada de escaneos.

        Args:
            request: Solicitud con hallazgos y contexto.

        Returns:
            EvidenceAnalysisResponse con análisis y riesgo.
        """
        ...

    @abstractmethod
    async def explain_finding(
        self, request: FindingExplanationRequest
    ) -> FindingExplanationResponse:
        """Explica un hallazgo de seguridad en lenguaje natural.

        Args:
            request: Solicitud con el hallazgo a explicar.

        Returns:
            FindingExplanationResponse con explicación detallada.
        """
        ...

    @abstractmethod
    async def suggest_remediation(
        self, request: RemediationRequest
    ) -> RemediationResponse:
        """Sugiere pasos de remediación para un hallazgo.

        Args:
            request: Solicitud con contexto del hallazgo.

        Returns:
            RemediationResponse con pasos concretos.
        """
        ...

    @abstractmethod
    async def health_check(self) -> bool:
        """Verifica que el proveedor esté disponible.

        Returns:
            True si el proveedor responde correctamente.
        """
        ...

    @abstractmethod
    async def complete(
        self,
        prompt: str,
        system_prompt: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> str:
        """Método bajo nivel para completar texto con el modelo.

        Args:
            prompt: Prompt del usuario.
            system_prompt: Prompt del sistema (opcional).
            temperature: Temperatura de muestreo (opcional).
            max_tokens: Máximo de tokens a generar (opcional).

        Returns:
            Texto generado por el modelo.
        """
        ...

    def _format_findings_for_prompt(self, findings: list[dict[str, Any]]) -> str:
        """Formatea hallazgos para incluir en prompts."""
        if not findings:
            return "No findings available."

        formatted = []
        for i, f in enumerate(findings, 1):
            parts = [
                f"Finding #{i}:",
                f"  - Title: {f.get('title', 'Unknown')}",
                f"  - Severity: {f.get('severity', 'Unknown')}",
                f"  - Description: {f.get('description', 'No description')[:200]}",
            ]
            if f.get("url"):
                parts.append(f"  - URL: {f['url']}")
            if f.get("cwe"):
                parts.append(f"  - CWE: {f['cwe']}")
            if f.get("evidence"):
                parts.append(f"  - Evidence: {f['evidence'][:150]}")
            formatted.append("\n".join(parts))

        return "\n\n".join(formatted)
