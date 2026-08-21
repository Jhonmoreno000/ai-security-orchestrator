import json
import os
import uuid
from pathlib import Path
from typing import List

import structlog

from app.orchestrator.base_runner import BaseToolRunner
from app.schemas.runner import FindingBase, ToolType

logger = structlog.get_logger()

NUCLEI_DOCKER_IMAGE = os.getenv("NUCLEI_DOCKER_IMAGE", "projectdiscovery/nuclei:latest")
NUCLEI_MEMORY_LIMIT = os.getenv("NUCLEI_MEMORY_LIMIT", "512m")
NUCLEI_CPU_QUOTA = int(os.getenv("NUCLEI_CPU_QUOTA", "50000"))


class NucleiRunner(BaseToolRunner):
    """Runner para ProjectDiscovery Nuclei.

    Ejecuta escaneos de vulnerabilidades basados en templates
    contra URLs o repositorios.

    Comando: nuclei -u <target> -json-export <output_file>
    """

    def __init__(self):
        super().__init__(
            docker_image=NUCLEI_DOCKER_IMAGE,
            memory_limit=NUCLEI_MEMORY_LIMIT,
            cpu_quota=NUCLEI_CPU_QUOTA,
        )
        self._artifacts: list[str] = []

    def validate_input(self, params: dict) -> bool:
        target = params.get("target", "")
        if not target:
            logger.error("nuclei_validation_failed", error="Target es requerido")
            return False

        timeout = params.get("timeout", 300)
        if timeout < 30:
            logger.error("nuclei_validation_failed", error="Timeout minimo: 30 segundos")
            return False

        return True

    def build_command(self, params: dict) -> list[str]:
        target = params.get("target", "")
        options = params.get("options", {})

        output_file = f"/tmp/nuclei_{uuid.uuid4().hex[:8]}.json"

        cmd = [
            "nuclei",
            "-u", target,
            "-json-export", output_file,
            "-silent",
        ]

        if "tags" in options:
            tags = options["tags"]
            if isinstance(tags, list):
                cmd.extend(["-tags", ",".join(tags)])
            else:
                cmd.extend(["-tags", str(tags)])

        if "severity" in options:
            severity = options["severity"]
            if isinstance(severity, list):
                cmd.extend(["-severity", ",".join(severity)])
            else:
                cmd.extend(["-severity", str(severity)])

        if "templates" in options:
            templates = options["templates"]
            if isinstance(templates, list):
                cmd.extend(["-t", ",".join(templates)])
            else:
                cmd.extend(["-t", str(templates)])

        if "rate_limit" in options:
            cmd.extend(["-rate-limit", str(options["rate_limit"])])

        cmd.extend(["-o", output_file])

        self._artifacts = [output_file]
        self._output_file = output_file

        return cmd

    def collect_artifacts(self) -> list[str]:
        return self._artifacts.copy()

    def parse_and_normalize(self, raw_output: str) -> list[FindingBase]:
        findings: list[FindingBase] = []

        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
                if not isinstance(data, dict):
                    continue

                info = data.get("info", {})
                if not isinstance(info, dict):
                    info = {}

                classification = data.get("classification", {})
                if not isinstance(classification, dict):
                    classification = {}

                severity_str = info.get("severity", "unknown")
                severity = self._map_nuclei_severity(severity_str)

                cwe_raw = classification.get("cwe", [None])
                cwe = cwe_raw[0] if isinstance(cwe_raw, list) and cwe_raw else cwe_raw

                title = info.get("name", data.get("template-id", "Unknown"))
                endpoint = data.get("matched-at", data.get("host", ""))

                findings.append(FindingBase(
                    title=title,
                    description=info.get("description", ""),
                    severity=severity,
                    confidence="high",
                    cwe=cwe,
                    owasp=None,
                    cvss_score=classification.get("cvss-score"),
                    evidence=data.get("extracted-results"),
                    remediation=None,
                    reference=info.get("reference"),
                    url=endpoint,
                    file_path=None,
                    line_number=None,
                    status="OPEN",
                    fingerprint=self._generate_fingerprint(title, endpoint, cwe),
                    scanner="nuclei",
                    raw_id=data.get("template-id"),
                    metadata={
                        "nuclei_template": data.get("template-id"),
                        "nuclei_matcher": data.get("matcher-name"),
                    },
                ))
            except (json.JSONDecodeError, TypeError, AttributeError):
                findings.append(FindingBase(
                    title="Nuclei raw finding",
                    description=line[:500],
                    severity="MEDIUM",
                    confidence="medium",
                    cwe=None,
                    scanner="nuclei",
                    evidence=line[:500],
                ))

        return findings

    def _map_nuclei_severity(self, severity: str) -> str:
        mapping = {
            "critical": "CRITICAL",
            "high": "HIGH",
            "medium": "MEDIUM",
            "low": "LOW",
            "info": "INFO",
            "unknown": "INFO",
        }
        return mapping.get(severity.lower(), "MEDIUM")
