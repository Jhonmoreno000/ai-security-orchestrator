import json
import os
import uuid
from pathlib import Path
from typing import List

import structlog

from app.orchestrator.base_runner import BaseToolRunner
from app.schemas.runner import FindingBase, ToolType

logger = structlog.get_logger()

SEMGREP_DOCKER_IMAGE = os.getenv("SEMGREP_DOCKER_IMAGE", "returntocorp/semgrep:latest")
SEMGREP_MEMORY_LIMIT = os.getenv("SEMGREP_MEMORY_LIMIT", "512m")
SEMGREP_CPU_QUOTA = int(os.getenv("SEMGREP_CPU_QUOTA", "50000"))


class SemgrepRunner(BaseToolRunner):
    """Runner para Semgrep (SAST).

    Ejecuta analisis estatico de codigo fuente buscando patrones
    de seguridad y vulnerabilidades.

    Comando: semgrep scan --config auto --json -o <output_file> <source_path>
    """

    def __init__(self):
        super().__init__(
            docker_image=SEMGREP_DOCKER_IMAGE,
            memory_limit=SEMGREP_MEMORY_LIMIT,
            cpu_quota=SEMGREP_CPU_QUOTA,
        )
        self._artifacts: list[str] = []

    def validate_input(self, params: dict) -> bool:
        target = params.get("target", "")
        if not target:
            logger.error("semgrep_validation_failed", error="Target es requerido")
            return False

        timeout = params.get("timeout", 300)
        if timeout < 30:
            logger.error("semgrep_validation_failed", error="Timeout minimo: 30 segundos")
            return False

        return True

    def build_command(self, params: dict) -> list[str]:
        target = params.get("target", "")
        options = params.get("options", {})

        output_file = f"/tmp/semgrep_{uuid.uuid4().hex[:8]}.json"

        cmd = [
            "semgrep", "scan",
            "--config", options.get("config", "auto"),
            "--json",
            "-o", output_file,
            target,
        ]

        if "severity" in options:
            cmd.extend(["--severity", str(options["severity"])])

        if "exclude" in options:
            excludes = options["exclude"]
            if isinstance(excludes, list):
                for ex in excludes:
                    cmd.extend(["--exclude", str(ex)])
            else:
                cmd.extend(["--exclude", str(excludes)])

        if "max_target_bytes" in options:
            cmd.extend(["--max-target-bytes", str(options["max_target_bytes"])])

        self._artifacts = [output_file]
        self._output_file = output_file

        return cmd

    def collect_artifacts(self) -> list[str]:
        return self._artifacts.copy()

    def parse_and_normalize(self, raw_output: str) -> list[FindingBase]:
        findings: list[FindingBase] = []

        try:
            data = json.loads(raw_output)
            if isinstance(data, dict):
                results = data.get("results", [])
                if isinstance(results, list):
                    for result in results:
                        finding = self._parse_finding(result)
                        if finding:
                            findings.append(finding)

                errors = data.get("errors", [])
                if isinstance(errors, list):
                    for error in errors:
                        findings.append(FindingBase(
                            title="Semgrep error",
                            description=str(error)[:500],
                            severity="INFO",
                            confidence="medium",
                            scanner="semgrep",
                        ))
        except (json.JSONDecodeError, TypeError):
            findings.extend(self._parse_plain_output(raw_output))

        return findings

    def _parse_finding(self, result: dict) -> FindingBase | None:
        extra = result.get("extra", {})
        if not isinstance(extra, dict):
            extra = {}

        metadata = extra.get("metadata", {})
        if not isinstance(metadata, dict):
            metadata = {}

        severity_str = metadata.get("severity", extra.get("severity", "WARNING"))
        severity = self._map_semgrep_severity(severity_str)

        cwe_list = metadata.get("cwe", [])
        cwe = cwe_list[0] if isinstance(cwe_list, list) and cwe_list else None

        path = result.get("path", "")
        line = result.get("start", {}).get("line") if isinstance(result.get("start"), dict) else None
        title = extra.get("message", result.get("check_id", "Semgrep finding"))
        endpoint = f"{path}:{line}" if line else path

        return FindingBase(
            title=title,
            description=extra.get("message", "")[:500],
            severity=severity,
            confidence=metadata.get("confidence", "medium"),
            cwe=cwe,
            owasp=None,
            cvss_score=metadata.get("cvss"),
            evidence=extra.get("lines", "")[:500],
            remediation=None,
            reference=metadata.get("source-rule-url"),
            url=endpoint,
            file_path=path,
            line_number=line,
            status="OPEN",
            fingerprint=self._generate_fingerprint(title, endpoint, cwe),
            scanner="semgrep",
            raw_id=result.get("check_id"),
            metadata={
                "semgrep_rule": result.get("check_id"),
            },
        )

    def _parse_plain_output(self, raw_output: str) -> list[FindingBase]:
        findings: list[FindingBase] = []

        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue

            if any(kw in line.lower() for kw in ["error", "warning", "info", "semgrep"]):
                severity = "MEDIUM"
                if "error" in line.lower():
                    severity = "HIGH"
                elif "info" in line.lower():
                    severity = "INFO"

                findings.append(FindingBase(
                    title="Semgrep output line",
                    description=line[:500],
                    severity=severity,
                    confidence="medium",
                    scanner="semgrep",
                    evidence=line[:500],
                ))

        return findings

    def _map_semgrep_severity(self, severity: str) -> str:
        mapping = {
            "ERROR": "HIGH",
            "WARNING": "MEDIUM",
            "INFO": "INFO",
            "HIGH": "HIGH",
            "MEDIUM": "MEDIUM",
            "LOW": "LOW",
        }
        return mapping.get(severity.upper(), "MEDIUM")
