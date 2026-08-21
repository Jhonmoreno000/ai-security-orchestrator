import json
import os
import uuid
from pathlib import Path
from typing import List

import structlog

from app.orchestrator.base_runner import BaseToolRunner
from app.schemas.runner import FindingBase, ToolType

logger = structlog.get_logger()

TRIVY_DOCKER_IMAGE = os.getenv("TRIVY_DOCKER_IMAGE", "aquasec/trivy:latest")
TRIVY_MEMORY_LIMIT = os.getenv("TRIVY_MEMORY_LIMIT", "512m")
TRIVY_CPU_QUOTA = int(os.getenv("TRIVY_CPU_QUOTA", "50000"))


class TrivyRunner(BaseToolRunner):
    """Runner para Trivy (Análisis de vulnerabilidades en contenedores/imágenes).

    Ejecuta escaneos de vulnerabilidades, configuración y secretos
    sobre imágenes Docker, repositorios o directorios.

    Comando: trivy fs --format json -o <output_file> <source_path>
    """

    def __init__(self):
        super().__init__(
            docker_image=TRIVY_DOCKER_IMAGE,
            memory_limit=TRIVY_MEMORY_LIMIT,
            cpu_quota=TRIVY_CPU_QUOTA,
        )
        self._artifacts: list[str] = []

    def validate_input(self, params: dict) -> bool:
        target = params.get("target", "")
        if not target:
            logger.error("trivy_validation_failed", error="Target es requerido")
            return False

        timeout = params.get("timeout", 300)
        if timeout < 30:
            logger.error("trivy_validation_failed", error="Timeout minimo: 30 segundos")
            return False

        return True

    def build_command(self, params: dict) -> list[str]:
        target = params.get("target", "")
        options = params.get("options", {})

        output_file = f"/tmp/trivy_{uuid.uuid4().hex[:8]}.json"

        cmd = [
            "trivy", "fs",
            "--format", "json",
            "-o", output_file,
            target,
        ]

        if "severity" in options:
            cmd.extend(["--severity", str(options["severity"])])

        if "scanners" in options:
            scanners = options["scanners"]
            if isinstance(scanners, list):
                cmd.extend(["--scanners", ",".join(scanners)])
            else:
                cmd.extend(["--scanners", str(scanners)])

        if options.get("skip_db_update"):
            cmd.append("--skip-db-update")

        if options.get("timeout"):
            cmd.extend(["--timeout", str(options["timeout"])])

        self._artifacts = [output_file]
        self._output_file = output_file

        return cmd

    def collect_artifacts(self) -> list[str]:
        return self._artifacts.copy()

    def parse_and_normalize(self, raw_output: str) -> list[FindingBase]:
        findings: list[FindingBase] = []

        try:
            data = json.loads(raw_output)
            if not isinstance(data, dict):
                return findings

            results = data.get("Results", [])
            if not isinstance(results, list):
                return findings

            for result in results:
                findings.extend(self._parse_result(result))

        except (json.JSONDecodeError, TypeError):
            findings.extend(self._parse_plain_output(raw_output))

        return findings

    def _parse_result(self, result: dict) -> list[FindingBase]:
        findings: list[FindingBase] = []
        target_name = result.get("Target", "")
        vulnerabilities = result.get("Vulnerabilities", [])

        if not isinstance(vulnerabilities, list):
            return findings

        for vuln in vulnerabilities:
            if not isinstance(vuln, dict):
                continue

            severity_str = vuln.get("Severity", "UNKNOWN")
            severity = self._map_trivy_severity(severity_str)

            cvss_score = None
            cvss_data = vuln.get("CVSS", {})
            if isinstance(cvss_data, dict):
                for vendor_score in cvss_data.values():
                    if isinstance(vendor_score, dict):
                        cvss_score = vendor_score.get("V3Score") or vendor_score.get("V2Score")
                        if cvss_score is not None:
                            break

            vuln_id = vuln.get("VulnerabilityID", "Unknown")
            pkg_name = vuln.get("PkgName", "unknown")
            title = f"{vuln_id} in {pkg_name}"
            endpoint = target_name

            findings.append(FindingBase(
                title=title,
                description=vuln.get("Description", "")[:500],
                severity=severity,
                confidence="high",
                cwe=None,
                owasp=None,
                cvss_score=cvss_score,
                evidence=f"Package: {pkg_name}, Installed: {vuln.get('InstalledVersion')}, Fixed: {vuln.get('FixedVersion')}",
                remediation=vuln.get("FixedVersion"),
                reference=vuln.get("PrimaryURL"),
                url=endpoint,
                file_path=None,
                line_number=None,
                status="OPEN",
                fingerprint=self._generate_fingerprint(title, endpoint, None),
                scanner="trivy",
                raw_id=vuln_id,
                metadata={
                    "trivy_pkg": pkg_name,
                    "trivy_installed": vuln.get("InstalledVersion"),
                    "trivy_fixed": vuln.get("FixedVersion"),
                },
            ))

        return findings

    def _parse_plain_output(self, raw_output: str) -> list[FindingBase]:
        findings: list[FindingBase] = []

        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue

            severity = "INFO"
            if "CRITICAL" in line:
                severity = "CRITICAL"
            elif "HIGH" in line:
                severity = "HIGH"
            elif "MEDIUM" in line:
                severity = "MEDIUM"
            elif "LOW" in line:
                severity = "LOW"

            if any(kw in line for kw in ["CVE-", "Vulnerability", "Critical", "High", "Medium"]):
                findings.append(FindingBase(
                    title="Trivy finding",
                    description=line[:500],
                    severity=severity,
                    confidence="medium",
                    scanner="trivy",
                    evidence=line[:500],
                ))

        return findings

    def _map_trivy_severity(self, severity: str) -> str:
        mapping = {
            "CRITICAL": "CRITICAL",
            "HIGH": "HIGH",
            "MEDIUM": "MEDIUM",
            "LOW": "LOW",
            "UNKNOWN": "INFO",
        }
        return mapping.get(severity.upper(), "MEDIUM")
