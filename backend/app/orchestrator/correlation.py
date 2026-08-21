from typing import List, Dict, Optional
from collections import defaultdict

import structlog

from app.schemas.runner import FindingBase, SeverityLevel

logger = structlog.get_logger()

SEVERITY_ORDER = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}


def _severity_value(severity: str) -> int:
    return SEVERITY_ORDER.get(severity.upper(), 0)


def _max_severity(a: str, b: str) -> str:
    a_val = _severity_value(a)
    b_val = _severity_value(b)
    if a_val >= b_val:
        return a.upper()
    return b.upper()


class CorrelationEngine:
    """Motor de correlacion y deduplicacion de hallazgos.

    Procesa la lista de FindingBase producidos por los runners
    antes de persistir en PostgreSQL.

    Flujo:
    1. Agrupa hallazgos por fingerprint
    2. Fusiona evidencias de multiples fuentes
    3. Ajusta severidad y confianza segun concurrencia
    """

    def correlate(self, findings: List[FindingBase]) -> List[FindingBase]:
        """Procesa la lista de findings y retorna una lista deduplicada.

        Args:
            findings: Lista completa de hallazgos generados en el escaneo.

        Returns:
            Lista de hallazgos correlacionados y deduplicados.
        """
        if not findings:
            return []

        grouped: Dict[str, List[FindingBase]] = defaultdict(list)
        for finding in findings:
            fp = finding.fingerprint or self._generate_temp_key(finding)
            grouped[fp].append(finding)

        correlated: List[FindingBase] = []
        for fp, group in grouped.items():
            if len(group) == 1:
                correlated.append(group[0])
            else:
                merged = self._merge_group(group)
                correlated.append(merged)

        logger.info(
            "correlation_completed",
            total_input=len(findings),
            total_output=len(correlated),
            duplicates_removed=len(findings) - len(correlated),
        )

        return correlated

    def _merge_group(self, group: List[FindingBase]) -> FindingBase:
        """Fusiona un grupo de hallazgos con el mismo fingerprint.

        Conserva el primer finding como base y actualiza campos
        con informacion de todas las fuentes.
        """
        base = group[0].model_copy(deep=True)

        sources = []
        raw_evidences = []
        seen_sources = set()

        for finding in group:
            scanner = finding.scanner.value if hasattr(finding.scanner, "value") else str(finding.scanner)
            if scanner not in seen_sources:
                sources.append(scanner)
                seen_sources.add(scanner)
                raw_evidences.append({
                    "tool": scanner,
                    "detail": finding.evidence or finding.description or "",
                })

        base.evidence = {
            "sources": sources,
            "raw_evidences": raw_evidences,
        }

        base.severity = self._resolve_severity(group)
        base.confidence = self._resolve_confidence(group)

        if base.cvss_score is None:
            for f in group:
                if f.cvss_score is not None:
                    base.cvss_score = f.cvss_score
                    break

        if base.remediation is None:
            for f in group:
                if f.remediation is not None:
                    base.remediation = f.remediation
                    break

        if base.reference is None:
            for f in group:
                if f.reference is not None:
                    base.reference = f.reference
                    break

        if base.owasp is None:
            for f in group:
                if f.owasp is not None:
                    base.owasp = f.owasp
                    break

        base.metadata["correlated_from"] = [
            {
                "scanner": f.scanner.value if hasattr(f.scanner, "value") else str(f.scanner),
                "raw_id": f.raw_id,
            }
            for f in group
        ]
        base.metadata["correlation_sources"] = sources

        logger.info(
            "findings_merged",
            fingerprint=base.fingerprint,
            sources=sources,
            merged_count=len(group),
        )

        return base

    def _resolve_severity(self, group: List[FindingBase]) -> SeverityLevel:
        """Resuelve la severidad tomando el maximo del grupo."""
        max_sev = "INFO"
        for finding in group:
            sev = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
            max_sev = _max_severity(max_sev, sev)
        return SeverityLevel(max_sev)

    def _resolve_confidence(self, group: List[FindingBase]) -> str:
        """Resuelve la confianza segun numero de herramientas que detectaron.

        1 herramienta: mantiene confidence original
        2 herramientas: HIGH
        3+ herramientas: CONFIRMED
        """
        unique_scanners = set()
        for f in group:
            scanner = f.scanner.value if hasattr(f.scanner, "value") else str(f.scanner)
            unique_scanners.add(scanner)

        count = len(unique_scanners)
        if count >= 3:
            return "CONFIRMED"
        elif count == 2:
            return "HIGH"
        else:
            return group[0].confidence

    def _generate_temp_key(self, finding: FindingBase) -> str:
        """Genera una clave temporal para hallazgos sin fingerprint."""
        parts = [
            finding.scanner.value if hasattr(finding.scanner, "value") else str(finding.scanner),
            finding.title or "",
            finding.url or "",
            finding.file_path or "",
        ]
        return "|".join(parts)
