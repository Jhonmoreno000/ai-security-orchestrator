import json
from typing import Any

import httpx
import structlog

from app.ai.base_provider import BaseAIProvider
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

SYSTEM_PROMPTS = {
    "plan": """Eres un experto en ciberseguridad y testing de seguridad de aplicaciones.
Tu tarea es generar planes de escaneo de seguridad optimizados.
Responde SIEMPRE en formato JSON válido con la estructura:
{
    "tools": [{"tool": "nombre", "config": {}}],
    "strategy": "descripción de la estrategia",
    "estimated_duration_seconds": 300,
    "reasoning": "explicación de por qué esta estrategia"
}""",

    "analyze": """Eres un analista de seguridad experto.
Analiza los hallazgos de seguridad y proporciona un análisis detallado.
Responde en formato JSON:
{
    "summary": "resumen ejecutivo",
    "risk_score": 0.0-10.0,
    "critical_paths": ["ruta crítica 1"],
    "attack_vectors": [{"vector": "...", "description": "..."}],
    "recommendations": ["recomendación 1"],
    "confidence": 0.0-1.0
}""",

    "explain": """Eres un comunicador de seguridad experto.
Explica hallazgos de seguridad de forma clara y técnica.
Responde en formato JSON:
{
    "title": "título del hallazgo",
    "explanation": "explicación detallada",
    "impact": "impacto en el negocio",
    "remediation": "cómo solucionarlo",
    "references": ["referencia 1"]
}""",

    "remediate": """Eres un ingeniero de seguridad experto.
Proporciona pasos concretos de remediación para hallazgos de seguridad.
Responde en formato JSON:
{
    "short_fix": "corrección rápida",
    "detailed_steps": ["paso 1", "paso 2"],
    "code_example": "ejemplo de código si aplica",
    "references": ["referencia 1"],
    "estimated_effort": "low/medium/high"
}""",
}


class OllamaProvider(BaseAIProvider):
    """Proveedor de IA local usando Ollama.

    Características:
    - Ejecución 100% local (privacidad máxima)
    - Soporte para múltiples modelos (codellama, llama2, mistral)
    - API REST compatible con Ollama
    - Fallback automático si el modelo no responde
    """

    def __init__(self, config: AIProviderConfig | None = None):
        super().__init__(config or AIProviderConfig())
        self._client: httpx.AsyncClient | None = None

    @property
    def provider_name(self) -> str:
        return "ollama"

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.config.base_url,
                timeout=httpx.Timeout(self.config.timeout, connect=10.0),
            )
        return self._client

    async def health_check(self) -> bool:
        """Verifica que Ollama esté disponible."""
        try:
            client = await self._get_client()
            response = await client.get("/api/tags")
            self._is_healthy = response.status_code == 200
            if self._is_healthy:
                models = response.json().get("models", [])
                logger.info(
                    "ollama_health_ok",
                    models=[m.get("name") for m in models],
                )
            return self._is_healthy
        except Exception as e:
            logger.error("ollama_health_check_failed", error=str(e))
            self._is_healthy = False
            return False

    async def complete(
        self,
        prompt: str,
        system_prompt: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> str:
        """Genera texto usando Ollama."""
        try:
            client = await self._get_client()

            payload: dict[str, Any] = {
                "model": self.config.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": temperature or self.config.temperature,
                    "num_predict": max_tokens or self.config.max_tokens,
                },
            }

            if system_prompt:
                payload["system"] = system_prompt

            response = await client.post("/api/generate", json=payload)

            if response.status_code != 200:
                logger.error(
                    "ollama_generate_failed",
                    status=response.status_code,
                    body=response.text[:500],
                )
                return ""

            data = response.json()
            return data.get("response", "")

        except httpx.TimeoutException:
            logger.error("ollama_timeout", model=self.config.model)
            return ""
        except Exception as e:
            logger.error("ollama_generate_error", error=str(e))
            return ""

    async def generate_plan(self, request: PlanRequest) -> PlanResponse:
        """Genera plan de escaneo usando Ollama."""
        prompt = f"""Genera un plan de escaneo de seguridad para:
- Objetivo: {request.target}
- Tipo de escaneo: {request.scan_type}
- Contexto adicional: {json.dumps(request.context, indent=2)}

{self._format_findings_for_prompt(request.previous_findings)}

Genera un plan optimizado considerando:
1. Las mejores herramientas para este tipo de objetivo
2. El orden óptimo de ejecución
3. La estimación de tiempo total"""

        response_text = await self.complete(
            prompt=prompt,
            system_prompt=SYSTEM_PROMPTS["plan"],
        )

        try:
            plan_data = json.loads(response_text)
            return PlanResponse(
                tools=plan_data.get("tools", []),
                strategy=plan_data.get("strategy", ""),
                estimated_duration_seconds=plan_data.get("estimated_duration_seconds", 300),
                reasoning=plan_data.get("reasoning"),
                metadata={"model": self.config.model, "provider": self.provider_name},
            )
        except json.JSONDecodeError:
            logger.warning("ollama_plan_parse_failed", response=response_text[:200])
            return PlanResponse(
                tools=[],
                strategy="Plan por defecto: baseline scan con ZAP",
                reasoning="No se pudo generar plan personalizado",
                metadata={"model": self.config.model, "fallback": True},
            )

    async def analyze_evidence(
        self, request: EvidenceAnalysisRequest
    ) -> EvidenceAnalysisResponse:
        """Analiza evidencia de hallazgos usando Ollama."""
        prompt = f"""Analiza los siguientes hallazgos de seguridad:

{self._format_findings_for_prompt(request.findings)}

Contexto del objetivo:
{json.dumps(request.target_info, indent=2)}

Proporciona un análisis completo con score de riesgo, vectores de ataque y recomendaciones."""

        response_text = await self.complete(
            prompt=prompt,
            system_prompt=SYSTEM_PROMPTS["analyze"],
        )

        try:
            data = json.loads(response_text)
            return EvidenceAnalysisResponse(
                summary=data.get("summary", ""),
                risk_score=min(10.0, max(0.0, data.get("risk_score", 0.0))),
                critical_paths=data.get("critical_paths", []),
                attack_vectors=data.get("attack_vectors", []),
                recommendations=data.get("recommendations", []),
                confidence=min(1.0, max(0.0, data.get("confidence", 0.5))),
                metadata={"model": self.config.model, "provider": self.provider_name},
            )
        except json.JSONDecodeError:
            return EvidenceAnalysisResponse(
                summary="Análisis no disponible",
                risk_score=5.0,
                confidence=0.0,
                metadata={"model": self.config.model, "fallback": True},
            )

    async def explain_finding(
        self, request: FindingExplanationRequest
    ) -> FindingExplanationResponse:
        """Explica un hallazgo usando Ollama."""
        finding = request.finding

        prompt = f"""Explica el siguiente hallazgo de seguridad en detalle:

Título: {finding.get('title', 'Unknown')}
Severidad: {finding.get('severity', 'Unknown')}
Descripción: {finding.get('description', 'No description')}
CWE: {finding.get('cwe', 'N/A')}
URL/Archivo: {finding.get('url', finding.get('file_path', 'N/A'))}
Evidencia: {finding.get('evidence', 'No evidence')}

Proporciona:
1. Una explicación técnica clara
2. El impacto potencial
3. Cómo se explota
4. Recomendaciones de remediación"""

        response_text = await self.complete(
            prompt=prompt,
            system_prompt=SYSTEM_PROMPTS["explain"],
        )

        try:
            data = json.loads(response_text)
            return FindingExplanationResponse(
                title=data.get("title", finding.get("title", "")),
                explanation=data.get("explanation", ""),
                impact=data.get("impact", ""),
                remediation=data.get("remediation"),
                references=data.get("references", []),
                metadata={"model": self.config.model, "provider": self.provider_name},
            )
        except json.JSONDecodeError:
            return FindingExplanationResponse(
                title=finding.get("title", ""),
                explanation=f"Hallazgo de severidad {finding.get('severity', 'unknown')}",
                impact="Requiere evaluación manual",
                metadata={"model": self.config.model, "fallback": True},
            )

    async def suggest_remediation(
        self, request: RemediationRequest
    ) -> RemediationResponse:
        """Sugiere remediación usando Ollama."""
        finding = request.finding

        prompt = f"""Sugiere pasos concretos de remediación para:

Hallazgo: {finding.get('title', 'Unknown')}
Severidad: {finding.get('severity', 'Unknown')}
Descripción: {finding.get('description', 'No description')}
CWE: {finding.get('cwe', 'N/A')}

Contexto adicional:
- Stack tecnológico: {', '.join(request.tech_stack) if request.tech_stack else 'No especificado'}
- Prioridad: {request.priority}
- Código relacionado: {request.code_context[:500] if request.code_context else 'No disponible'}

Proporciona pasos específicos y ejecutables."""

        response_text = await self.complete(
            prompt=prompt,
            system_prompt=SYSTEM_PROMPTS["remediate"],
        )

        try:
            data = json.loads(response_text)
            return RemediationResponse(
                short_fix=data.get("short_fix", ""),
                detailed_steps=data.get("detailed_steps", []),
                code_example=data.get("code_example"),
                references=data.get("references", []),
                estimated_effort=data.get("estimated_effort", "unknown"),
                metadata={"model": self.config.model, "provider": self.provider_name},
            )
        except json.JSONDecodeError:
            return RemediationResponse(
                short_fix="Revisar y corregir manualmente",
                detailed_steps=["Identificar la vulnerabilidad", "Aplicar corrección", "Verificar fix"],
                estimated_effort="medium",
                metadata={"model": self.config.model, "fallback": True},
            )

    async def close(self):
        """Cierra las conexiones HTTP."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
