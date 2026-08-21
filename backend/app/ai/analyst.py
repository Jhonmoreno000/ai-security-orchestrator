import json
from typing import Any, Optional
from uuid import UUID

import structlog
from sqlalchemy.orm import Session

from app.ai.gateway import AIGateway
from app.models.entities import Finding
from app.schemas.ai_analyst import (
    FindingAnalysisRequest,
    FindingAnalysisResult,
    FalsePositiveLikelihood,
)

logger = structlog.get_logger()

SYSTEM_PROMPT = """You are a Senior Cybersecurity Auditor with 15+ years of experience.

Your role:
- Analyze security findings and provide clear, actionable explanations.
- Write remediation code in the SAME language/framework as the target project.
- Never invent vulnerabilities; only process confirmed findings from security engines.
- Use plain language; avoid redundant jargon.
- Always assess false positive likelihood honestly.

Rules:
1. Respond ONLY in valid JSON format.
2. summary: 2-3 sentences explaining the problem clearly.
3. business_impact: What happens if this vulnerability is exploited.
4. remediation_steps: Concrete technical steps to fix it.
5. code_example: Working code in the project's technology (FastAPI/Python, Express/Node, etc.).
6. false_positive_likelihood: LOW, MEDIUM, or HIGH with reasoning.

The project's tech stack will be provided. Always write code examples in that stack's language."""

ANALYSIS_PROMPT_TEMPLATE = """Analyze this security finding and respond in JSON format.

Finding:
- Title: {title}
- Severity: {severity}
- CWE: {cwe}
- Endpoint: {endpoint}
- Evidence: {evidence}
- Scanner: {scanner}

Project Tech Stack: {tech_stack}

Respond with this exact JSON structure:
{{
  "summary": "2-3 sentence executive summary",
  "business_impact": "clear explanation of real business risk",
  "remediation_steps": ["step1", "step2", "step3"],
  "code_example": "working code fix in the project's language or null",
  "false_positive_likelihood": "LOW|MEDIUM|HIGH",
  "false_positive_reasoning": "why this assessment"
}}"""


class AIAnalyst:
    """AI Analyst module que enriquece findings con analisis inteligente.

    Principios:
    - Evidence-first: solo procesa findings confirmados por motores
    - No inventa vulnerabilidades
    - Codigo de remediacion en el stack detectado del proyecto
    - Fallback automatico si la IA falla
    """

    def __init__(self, gateway: AIGateway | None = None):
        self._gateway = gateway or AIGateway()

    async def analyze_finding(
        self,
        finding: dict[str, Any],
        stack_summary: str,
    ) -> FindingAnalysisResult:
        """Analiza un finding y retorna analisis enriquecido.

        Args:
            finding: Dict con datos del finding (title, evidence, cwe, endpoint, severity, scanner).
            stack_summary: Stack tecnologico detectado por ProjectAnalyzer.

        Returns:
            FindingAnalysisResult con analisis completo.
        """
        request = FindingAnalysisRequest(
            title=finding.get("title", "Unknown"),
            evidence=finding.get("evidence"),
            cwe=finding.get("cwe"),
            endpoint=finding.get("url") or finding.get("endpoint"),
            severity=finding.get("severity"),
            scanner=finding.get("scanner"),
            tech_stack=[stack_summary] if stack_summary else [],
        )

        sanitized = self._gateway.sanitize_dict_for_ai(request.model_dump())

        prompt = ANALYSIS_PROMPT_TEMPLATE.format(
            title=sanitized.get("title", ""),
            severity=sanitized.get("severity", "UNKNOWN"),
            cwe=sanitized.get("cwe", "N/A"),
            endpoint=sanitized.get("endpoint", "N/A"),
            evidence=sanitized.get("evidence", "N/A"),
            scanner=sanitized.get("scanner", "unknown"),
            tech_stack=stack_summary or "Not detected",
        )

        try:
            provider = self._gateway.provider
            if provider is None:
                logger.warning("ai_provider_unavailable")
                return self._build_fallback(request)

            raw_response = await provider.complete(
                prompt=prompt,
                system_prompt=SYSTEM_PROMPT,
                temperature=0.2,
                max_tokens=2048,
            )

            result = self._parse_response(raw_response, request)

            logger.info(
                "finding_analyzed",
                finding_title=request.title,
                fp_likelihood=result.false_positive_likelihood,
            )
            return result

        except Exception as e:
            logger.error("finding_analysis_error", error=str(e))
            return self._build_fallback(request)

    def update_finding_in_db(
        self,
        db: Session,
        finding_id: UUID,
        analysis: FindingAnalysisResult,
    ) -> bool:
        """Actualiza los campos remediation y evidence del finding en la BD.

        Args:
            db: Sesion de SQLAlchemy activa.
            finding_id: ID del finding a actualizar.
            analysis: Resultado del analisis IA.

        Returns:
            True si se actualizo correctamente, False si no encontro el finding.
        """
        finding = db.query(Finding).filter(Finding.id == finding_id).first()
        if not finding:
            logger.warning("finding_not_found_for_update", finding_id=str(finding_id))
            return False

        existing_evidence = finding.evidence or ""
        ai_evidence = (
            f"\n\n[AI Analysis]\n"
            f"Summary: {analysis.summary}\n"
            f"Business Impact: {analysis.business_impact}\n"
            f"False Positive Likelihood: {analysis.false_positive_likelihood.value}"
        )
        finding.evidence = existing_evidence + ai_evidence

        if analysis.remediation_steps:
            finding.remediation = "\n".join(
                f"{i+1}. {step}" for i, step in enumerate(analysis.remediation_steps)
            )

        if analysis.code_example:
            finding.remediation = (finding.remediation or "") + f"\n\n[Code Example]\n{analysis.code_example}"

        db.commit()
        db.refresh(finding)

        logger.info(
            "finding_enriched_in_db",
            finding_id=str(finding_id),
            has_remediation=bool(analysis.remediation_steps),
            has_code=bool(analysis.code_example),
        )
        return True

    def _parse_response(
        self,
        raw_response: str,
        request: FindingAnalysisRequest,
    ) -> FindingAnalysisResult:
        """Parsea la respuesta JSON del modelo AI."""
        try:
            json_str = self._extract_json(raw_response)
            data = json.loads(json_str)
        except (json.JSONDecodeError, ValueError):
            logger.warning("ai_response_parse_failed", raw=raw_response[:200])
            return self._build_fallback(request)

        fp_str = data.get("false_positive_likelihood", "LOW").upper()
        try:
            fp_likelihood = FalsePositiveLikelihood(fp_str)
        except ValueError:
            fp_likelihood = FalsePositiveLikelihood.LOW

        return FindingAnalysisResult(
            summary=data.get("summary", ""),
            business_impact=data.get("business_impact", ""),
            remediation_steps=data.get("remediation_steps", []),
            code_example=data.get("code_example"),
            false_positive_likelihood=fp_likelihood,
            false_positive_reasoning=data.get("false_positive_reasoning", ""),
            metadata={"model_raw": raw_response[:500]},
        )

    def _extract_json(self, text: str) -> str:
        """Extrae JSON de la respuesta del modelo."""
        text = text.strip()
        if text.startswith("{"):
            return text

        start = text.find("{")
        end = text.rfind("}") + 1
        if start != -1 and end > start:
            return text[start:end]

        return text

    def _build_fallback(self, request: FindingAnalysisRequest) -> FindingAnalysisResult:
        """Construye resultado basico cuando la IA no esta disponible."""
        severity = (request.severity or "MEDIUM").upper()

        severity_explanations = {
            "CRITICAL": "This is a critical vulnerability that requires immediate attention.",
            "HIGH": "This is a high-severity vulnerability that should be addressed promptly.",
            "MEDIUM": "This is a medium-severity vulnerability that should be planned for remediation.",
            "LOW": "This is a low-severity vulnerability that should be reviewed.",
            "INFO": "This is an informational finding for awareness.",
        }

        summary = (
            f"{request.title} detected at {request.endpoint or 'unknown endpoint'}. "
            f"CWE: {request.cwe or 'N/A'}. "
            f"{severity_explanations.get(severity, severity_explanations['MEDIUM'])}"
        )

        business_impact = (
            f"If exploited, this {severity} severity vulnerability could compromise "
            f"the security of the affected component. Manual assessment recommended."
        )

        remediation_steps = [
            f"Review the finding at {request.endpoint or 'the reported endpoint'}",
            f"Validate if the vulnerability exists (CWE: {request.cwe or 'unknown'})",
            "Apply the recommended security patch or configuration change",
            "Re-scan to verify the fix",
        ]

        return FindingAnalysisResult(
            summary=summary,
            business_impact=business_impact,
            remediation_steps=remediation_steps,
            code_example=None,
            false_positive_likelihood=FalsePositiveLikelihood.MEDIUM,
            false_positive_reasoning="Unable to assess without AI provider; manual review recommended.",
            metadata={"fallback": True, "reason": "ai_provider_unavailable"},
        )
