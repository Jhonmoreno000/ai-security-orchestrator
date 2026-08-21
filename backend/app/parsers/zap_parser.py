import hashlib
import json
import re
from typing import Any

import structlog

from app.schemas.runner import FindingBase, FindingStatus, SeverityLevel, ToolType

logger = structlog.get_logger()


ZAP_SEVERITY_MAP = {
    "High": SeverityLevel.HIGH,
    "Medium": SeverityLevel.MEDIUM,
    "Low": SeverityLevel.LOW,
    "Informational": SeverityLevel.INFO,
    "Information": SeverityLevel.INFO,
    "3": SeverityLevel.HIGH,
    "2": SeverityLevel.MEDIUM,
    "1": SeverityLevel.LOW,
    "0": SeverityLevel.INFO,
}

ZAP_CONFIDENCE_MAP = {
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Confirmed": "high",
    "Tentative": "medium",
    "False Positive": "low",
    "3": "high",
    "2": "medium",
    "1": "low",
    "0": "low",
}


class ZAPParser:
    """Parser para la salida de OWASP ZAP.

    Mapeo de campos:
    - Alerta / Nombre → title
    - Risk (High, Medium, Low, Informational) → severity
    - Confidence → confidence
    - CWE ID → cwe
    - WASC ID / OWASP Top 10 → owasp
    - Description / Evidence / Solution → evidence y remediation

    Fingerprint: SHA256(title + endpoint + cwe)
    """

    def parse_json(self, raw_output: str) -> list[FindingBase]:
        """Parsea la salida JSON de ZAP.

        ZAP genera JSON con la estructura:
        {
            "site": [...],
            "alerts": [...],
            "statistics": {...}
        }
        """
        findings: list[FindingBase] = []

        try:
            data = self._extract_json_from_output(raw_output)
            if data is None:
                logger.warning("zap_no_json_found")
                return findings

            alerts = data.get("alerts", [])
            if isinstance(alerts, list):
                for alert in alerts:
                    finding = self._parse_alert(alert)
                    if finding:
                        findings.append(finding)

            sites = data.get("site", [])
            if isinstance(sites, list):
                for site in sites:
                    site_alerts = site.get("alerts", [])
                    for alert in site_alerts:
                        finding = self._parse_alert(alert)
                        if finding:
                            findings.append(finding)

        except (json.JSONDecodeError, TypeError, KeyError) as e:
            logger.error("zap_json_parse_error", error=str(e))

        return findings

    def parse_xml(self, raw_output: str) -> list[FindingBase]:
        """Parsea la salida XML de ZAP."""
        import xml.etree.ElementTree as ET

        findings: list[FindingBase] = []

        try:
            xml_match = re.search(r"<\?xml.*?\?>.*</alertitem>", raw_output, re.DOTALL)
            if not xml_match:
                xml_match = re.search(r"<alerts.*?</alerts>", raw_output, re.DOTALL)

            if not xml_match:
                return findings

            root = ET.fromstring(xml_match.group())

            for alert_item in root.iter("alertitem"):
                finding = self._parse_xml_alert(alert_item)
                if finding:
                    findings.append(finding)

        except ET.ParseError as e:
            logger.error("zap_xml_parse_error", error=str(e))

        return findings

    def parse_plain(self, raw_output: str) -> list[FindingBase]:
        """Parsea la salida plain text de ZAP (fallback)."""
        findings: list[FindingBase] = []

        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue

            if any(kw in line for kw in ["Alert", "WARN", "HIGH", "MEDIUM", "LOW", "INFO"]):
                severity = self._extract_severity_from_line(line)
                confidence = self._extract_confidence_from_line(line)
                title = self._extract_title_from_line(line)

                endpoint = self._extract_endpoint_from_line(line)
                cwe = None

                fingerprint = self._generate_fingerprint(title, endpoint, cwe)

                findings.append(FindingBase(
                    title=title,
                    description=line,
                    severity=severity,
                    confidence=confidence,
                    cwe=cwe,
                    owasp=None,
                    evidence=line,
                    remediation=None,
                    reference=None,
                    url=endpoint,
                    scanner=ToolType.ZAP,
                    fingerprint=fingerprint,
                    status=FindingStatus.OPEN,
                ))

        return findings

    def _extract_json_from_output(self, raw_output: str) -> dict[str, Any] | None:
        """Extrae el JSON de la salida de ZAP."""
        json_patterns = [
            r'\{[\s\S]*"site"[\s\S]*\}',
            r'\{[\s\S]*"alerts"[\s\S]*\}',
            r'\{[\s\S]*"statistics"[\s\S]*\}',
        ]

        for pattern in json_patterns:
            match = re.search(pattern, raw_output)
            if match:
                try:
                    return json.loads(match.group())
                except json.JSONDecodeError:
                    continue

        for line in raw_output.splitlines():
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                try:
                    data = json.loads(line)
                    if isinstance(data, dict) and ("alerts" in data or "site" in data):
                        return data
                except json.JSONDecodeError:
                    continue

        try:
            return json.loads(raw_output)
        except json.JSONDecodeError:
            return None

    def _parse_alert(self, alert: dict[str, Any]) -> FindingBase | None:
        """Parsea un alert individual de ZAP.

        Mapeo de campos:
        - alert["name"] o alert["alert"] → title
        - alert["riskdesc"] o alert["risk"] → severity
        - alert["confidence"] o alert["reliability"] → confidence
        - alert["cweid"] o alert["cwe"] → cwe
        - alert["wascid"] → owasp
        - alert["desc"] o alert["description"] → evidence (descripción)
        - alert["evidence"] o alert["otherinfo"] → evidence
        - alert["solution"] o alert["remediation"] → remediation
        - alert["url"] o alert["host"] → endpoint (url)
        """
        try:
            name = alert.get("name", alert.get("alert", "Unknown Alert"))
            if not name:
                return None

            description = alert.get("desc", alert.get("description", ""))
            if isinstance(description, str):
                description = self._strip_html(description)

            severity_str = alert.get("riskdesc", alert.get("risk", "Medium"))
            severity = ZAP_SEVERITY_MAP.get(severity_str, SeverityLevel.MEDIUM)

            confidence_str = alert.get("confidence", alert.get("reliability", "Medium"))
            confidence = ZAP_CONFIDENCE_MAP.get(confidence_str, "medium")

            cwe_id = alert.get("cweid", alert.get("cwe"))
            if cwe_id and not str(cwe_id).startswith("CWE-"):
                cwe_id = f"CWE-{cwe_id}"

            owasp_ref = alert.get("wascid")
            owasp = None
            if owasp_ref:
                owasp = f"WASC-{owasp_ref}"

            url = alert.get("url", alert.get("host", ""))
            evidence_desc = alert.get("desc", alert.get("description", ""))
            if isinstance(evidence_desc, str):
                evidence_desc = self._strip_html(evidence_desc)

            evidence_other = alert.get("evidence", alert.get("otherinfo", ""))

            evidence = evidence_other if evidence_other else evidence_desc

            solution = alert.get("solution", alert.get("remediation", ""))
            if isinstance(solution, str):
                solution = self._strip_html(solution)

            reference = alert.get("reference", "")
            if isinstance(reference, str):
                reference = self._strip_html(reference)

            endpoint = url or ""
            fingerprint = self._generate_fingerprint(name, endpoint, cwe_id)

            return FindingBase(
                title=name,
                description=description[:1000] if description else "",
                severity=severity,
                confidence=confidence,
                cwe=cwe_id,
                owasp=owasp,
                evidence=evidence[:500] if evidence else None,
                remediation=solution[:500] if solution else None,
                reference=reference[:500] if reference else None,
                url=url,
                scanner=ToolType.ZAP,
                fingerprint=fingerprint,
                raw_id=alert.get("pluginid"),
                status=FindingStatus.OPEN,
                metadata={
                    "zap_alert_ref": alert.get("pluginid"),
                    "count": alert.get("count"),
                },
            )
        except Exception as e:
            logger.warning("zap_alert_parse_error", alert=alert, error=str(e))
            return None

    def _parse_xml_alert(self, alert_elem) -> FindingBase | None:
        """Parsea un elemento XML alertitem."""
        import xml.etree.ElementTree as ET

        try:
            name = self._get_xml_text(alert_elem, "name")
            if not name:
                return None

            severity_str = self._get_xml_text(alert_elem, "riskdesc", "Medium")
            severity = ZAP_SEVERITY_MAP.get(severity_str, SeverityLevel.MEDIUM)

            confidence_str = self._get_xml_text(alert_elem, "confidence", "Medium")
            confidence = ZAP_CONFIDENCE_MAP.get(confidence_str, "medium")

            cwe_id = self._get_xml_text(alert_elem, "cweid")
            if cwe_id and not cwe_id.startswith("CWE-"):
                cwe_id = f"CWE-{cwe_id}"

            owasp_ref = self._get_xml_text(alert_elem, "wascid")
            owasp = None
            if owasp_ref:
                owasp = f"WASC-{owasp_ref}"

            url = self._get_xml_text(alert_elem, "url")
            endpoint = url or ""

            fingerprint = self._generate_fingerprint(name, endpoint, cwe_id)

            return FindingBase(
                title=name,
                description=self._get_xml_text(alert_elem, "desc", "")[:1000],
                severity=severity,
                confidence=confidence,
                cwe=cwe_id,
                owasp=owasp,
                evidence=self._get_xml_text(alert_elem, "evidence"),
                remediation=self._get_xml_text(alert_elem, "solution"),
                url=url,
                scanner=ToolType.ZAP,
                fingerprint=fingerprint,
                raw_id=self._get_xml_text(alert_elem, "pluginid"),
                status=FindingStatus.OPEN,
            )
        except Exception as e:
            logger.warning("zap_xml_alert_parse_error", error=str(e))
            return None

    def _get_xml_text(self, elem, tag: str, default: str = "") -> str:
        """Obtiene el texto de un elemento XML."""
        child = elem.find(tag)
        if child is not None and child.text:
            return child.text.strip()
        return default

    def _strip_html(self, text: str) -> str:
        """Elimina tags HTML de un texto."""
        if not text:
            return ""
        clean = re.sub(r"<[^>]+>", "", text)
        clean = re.sub(r"\s+", " ", clean)
        return clean.strip()

    def _extract_severity_from_line(self, line: str) -> SeverityLevel:
        """Extrae severidad de una línea de texto."""
        line_upper = line.upper()
        if "HIGH" in line_upper:
            return SeverityLevel.HIGH
        elif "MEDIUM" in line_upper:
            return SeverityLevel.MEDIUM
        elif "LOW" in line_upper:
            return SeverityLevel.LOW
        elif "INFO" in line_upper:
            return SeverityLevel.INFO
        return SeverityLevel.MEDIUM

    def _extract_confidence_from_line(self, line: str) -> str:
        """Extrae confianza de una línea de texto."""
        line_lower = line.lower()
        if "high confidence" in line_lower or "confirmed" in line_lower:
            return "high"
        elif "medium confidence" in line_lower or "tentative" in line_lower:
            return "medium"
        elif "low confidence" in line_lower:
            return "low"
        return "medium"

    def _extract_title_from_line(self, line: str) -> str:
        """Extrae título de una línea de texto."""
        if "]" in line:
            parts = line.split("]")
            if len(parts) > 1:
                title = parts[1].strip()
                return title[:200] if title else line[:200]
        if ":" in line:
            parts = line.split(":")
            if len(parts) > 1:
                return parts[1].strip()[:200]
        return line[:200]

    def _extract_endpoint_from_line(self, line: str) -> str:
        """Extrae endpoint/URL de una línea de texto."""
        url_pattern = r'https?://[^\s\]\)"]+'
        match = re.search(url_pattern, line)
        if match:
            return match.group()
        return ""

    def _generate_fingerprint(self, title: str, endpoint: str, cwe: str | None) -> str:
        """Genera un fingerprint SHA-256 único usando title + endpoint + cwe.

        Este fingerprint permite comparar hallazgos en futuros retests.
        """
        components = [
            title or "",
            endpoint or "",
            cwe or "",
        ]
        raw = "|".join(components)
        return hashlib.sha256(raw.encode()).hexdigest()[:32]
