import ipaddress
import os
import re
from typing import Any
from urllib.parse import urlparse

import structlog

from app.schemas.policy import (
    PolicyAction,
    PolicyValidationError,
    PolicyValidationResult,
    PolicyViolation,
    ResourceLimits,
    SecurityPlan,
    StepPolicy,
)

logger = structlog.get_logger()

JOB_TIMEOUT = int(os.getenv("JOB_TIMEOUT", "300"))
MAX_CONCURRENCY = int(os.getenv("MAX_CONCURRENCY", "2"))

ALLOWED_TOOLS = ["zap", "nuclei", "semgrep", "trivy", "nmap"]

DANGEROUS_METACHARACTERS = [
    ";",
    "&&",
    "||",
    "|",
    "`",
    "$(",
    "${",
    ">",
    ">>",
    "<",
    "\\n",
    "\\r",
]


class PolicyEngine:
    """Motor de politicas de seguridad para validar planes de ejecucion.

    Validaciones implementadas:
    1. validate_scope: Verifica que la URL del paso pertenezca estrictamente al scope
    2. Tool Allowlist: Solo ["zap", "nuclei", "semgrep", "trivy", "nmap"]
    3. sanitize_parameters: Revisa metacaracteres peligrosos (;, &&, |, `, $()
    4. validate_limits: Timeout no supere JOB_TIMEOUT, limite de jobs concurrentes
    """

    def __init__(self, job_timeout: int | None = None, max_concurrency: int | None = None):
        self._job_timeout = job_timeout or JOB_TIMEOUT
        self._max_concurrency = max_concurrency or MAX_CONCURRENCY

    def validate_plan(self, plan: SecurityPlan) -> PolicyValidationResult:
        """Valida un SecurityPlan completo contra las politicas configuradas.

        Flujo:
        1. validate_scope: Verificar URL pertenece al scope
        2. Tool Allowlist: Solo herramientas permitidas
        3. sanitize_parameters: Sin metacaracteres peligrosos
        4. validate_limits: Timeout y concurrencia

        Args:
            plan: SecurityPlan a validar.

        Returns:
            PolicyValidationResult con el resultado de la validacion.

        Raises:
            PolicyValidationError: Si hay violaciones DENY.
        """
        violations: list[PolicyViolation] = []
        warnings: list[PolicyViolation] = []

        logger.info(
            "policy_validation_started",
            target=plan.target,
            steps=len(plan.steps),
            scope_count=len(plan.scope),
        )

        scope_violations = self.validate_scope(plan)
        violations.extend(scope_violations)

        tool_violations = self._validate_tool_allowlist(plan)
        violations.extend(tool_violations)

        for step in plan.steps:
            param_violations = self.sanitize_parameters(step)
            violations.extend(param_violations)

        limit_violations = self.validate_limits(plan)
        violations.extend(limit_violations)

        has_denial = any(v.action == PolicyAction.DENY for v in violations)
        has_warnings = any(v.action == PolicyAction.WARN for v in violations)

        if has_denial:
            logger.warning(
                "policy_denied",
                target=plan.target,
                violations=[v.message for v in violations if v.action == PolicyAction.DENY],
            )
            raise PolicyValidationError(
                message=f"Plan denegado: {len([v for v in violations if v.action == PolicyAction.DENY])} violaciones",
                violations=violations,
            )

        if has_warnings:
            logger.info(
                "policy_warnings",
                target=plan.target,
                warnings=[v.message for v in violations if v.action == PolicyAction.WARN],
            )
        else:
            logger.info(
                "policy_approved",
                target=plan.target,
                steps=len(plan.steps),
            )

        return PolicyValidationResult(
            allowed=True,
            violations=violations,
            warnings=[v for v in violations if v.action == PolicyAction.WARN],
            applied_limits=ResourceLimits(
                max_timeout_seconds=self._job_timeout,
                max_concurrent_jobs=self._max_concurrency,
            ),
            metadata={
                "target": plan.target,
                "steps_validated": len(plan.steps),
                "tools_used": list(set(step.tool for step in plan.steps)),
            },
        )

    def validate_scope(self, plan: SecurityPlan) -> list[PolicyViolation]:
        """Validacion de Scope: Verifica que la URL del paso pertenezca estrictamente al scope.

        Bloquea direcciones IP privadas no autorizadas o dominios fuera de la lista blanca.

        Args:
            plan: SecurityPlan a validar.

        Returns:
            Lista de violaciones encontradas.
        """
        violations: list[PolicyViolation] = []

        for step in plan.steps:
            step_url = step.target_url

            in_scope = False
            for allowed in plan.scope:
                if self._url_matches_strict(step_url, allowed):
                    in_scope = True
                    break

            if not in_scope and plan.scope:
                violations.append(
                    PolicyViolation(
                        rule_id="SCOPE_OUT_OF_BOUNDS",
                        action=PolicyAction.DENY,
                        message=f"Step URL fuera del scope autorizado: {step_url}",
                        target=step_url,
                        details={
                            "step_tool": step.tool,
                            "allowed_scope": plan.scope,
                        },
                    )
                )

            if self._is_private_ip(step_url):
                violations.append(
                    PolicyViolation(
                        rule_id="PRIVATE_IP_BLOCKED",
                        action=PolicyAction.DENY,
                        message=f"IP privada no autorizada: {step_url}",
                        target=step_url,
                        details={"step_tool": step.tool},
                    )
                )

        return violations

    def _validate_tool_allowlist(self, plan: SecurityPlan) -> list[PolicyViolation]:
        """Lista Blanca de Herramientas: Solo ["zap", "nuclei", "semgrep", "trivy", "nmap"].

        Rechaza cualquier intento de ejecutar herramientas no listadas o comandos de shell directos.
        """
        violations: list[PolicyViolation] = []

        for step in plan.steps:
            if step.tool not in ALLOWED_TOOLS:
                violations.append(
                    PolicyViolation(
                        rule_id="TOOL_NOT_ALLOWED",
                        action=PolicyAction.DENY,
                        message=f"Herramienta no permitida: {step.tool}. Permitidas: {ALLOWED_TOOLS}",
                        target=step.target_url,
                        details={"tool": step.tool, "allowed_tools": ALLOWED_TOOLS},
                    )
                )

            shell_patterns = ["sh", "bash", "cmd", "powershell", "/bin/", "/usr/bin/"]
            for pattern in shell_patterns:
                if pattern in step.tool.lower():
                    violations.append(
                        PolicyViolation(
                            rule_id="SHELL_COMMAND_BLOCKED",
                            action=PolicyAction.DENY,
                            message=f"Comando de shell bloqueado: {step.tool}",
                            target=step.target_url,
                            details={"tool": step.tool},
                        )
                    )
                    break

        return violations

    def sanitize_parameters(self, step: StepPolicy) -> list[PolicyViolation]:
        """Validacion de Parametros Inseguros: Revisa metacaracteres peligrosos de terminal.

        Detecta: ;, &&, |, `, $()
        """
        violations: list[PolicyViolation] = []

        for key, value in step.parameters.items():
            if not isinstance(value, str):
                continue

            for metachar in DANGEROUS_METACHARACTERS:
                if metachar in value:
                    violations.append(
                        PolicyViolation(
                            rule_id="UNSAFE_PARAMETER",
                            action=PolicyAction.DENY,
                            message=f"Parametro '{key}' contiene metacaracter peligroso: '{metachar}'",
                            target=step.target_url,
                            details={
                                "parameter": key,
                                "metacharacter": metachar,
                                "value_preview": value[:100],
                            },
                        )
                    )
                    break

        return violations

    def validate_limits(self, plan: SecurityPlan) -> list[PolicyViolation]:
        """Control de Recursos y Limites: Timeout y concurrencia.

        Asegura que timeout_seconds no supere JOB_TIMEOUT.
        Limita la cantidad de jobs concurrentes permitidos.
        """
        violations: list[PolicyViolation] = []

        for step in plan.steps:
            if step.timeout_seconds > self._job_timeout:
                violations.append(
                    PolicyViolation(
                        rule_id="TIMEOUT_EXCEEDED",
                        action=PolicyAction.DENY,
                        message=f"Timeout excede limite global: {step.timeout_seconds}s > {self._job_timeout}s",
                        target=step.target_url,
                        details={
                            "step_tool": step.tool,
                            "requested": step.timeout_seconds,
                            "max_allowed": self._job_timeout,
                        },
                    )
                )

        if len(plan.steps) > self._max_concurrency:
            violations.append(
                PolicyViolation(
                    rule_id="CONCURRENCY_EXCEEDED",
                    action=PolicyAction.DENY,
                    message=f"Numero de steps excede concurrencia maxima: {len(plan.steps)} > {self._max_concurrency}",
                    target=plan.target,
                    details={
                        "steps_count": len(plan.steps),
                        "max_concurrency": self._max_concurrency,
                    },
                )
            )

        return violations

    def _url_matches_strict(self, target_url: str, allowed: str) -> bool:
        """Verifica si una URL coincide estrictamente con un target permitido."""
        try:
            target_parsed = urlparse(target_url)
            allowed_parsed = urlparse(allowed)

            if allowed_parsed.scheme and target_parsed.scheme != allowed_parsed.scheme:
                return False

            if allowed_parsed.hostname:
                if target_parsed.hostname != allowed_parsed.hostname:
                    if not target_parsed.hostname.endswith(f".{allowed_parsed.hostname}"):
                        return False

            if allowed_parsed.port and target_parsed.port != allowed_parsed.port:
                return False

            if allowed_parsed.path and allowed_parsed.path != "/":
                if not target_parsed.path.startswith(allowed_parsed.path):
                    return False

            return True
        except Exception:
            return False

    def _is_private_ip(self, url: str) -> bool:
        """Verifica si la URL apunta a una IP privada."""
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            if not hostname:
                return False

            try:
                ip = ipaddress.ip_address(hostname)
                return ip.is_private or ip.is_loopback or ip.is_reserved
            except ValueError:
                return False
        except Exception:
            return False
