import json
import os
from pathlib import Path
from urllib.parse import urlparse

import structlog

from app.orchestrator.base_runner import BaseToolRunner
from app.parsers.zap_parser import ZAPParser
from app.schemas.runner import FindingBase, ToolType

logger = structlog.get_logger()

ZAP_DOCKER_IMAGE = os.getenv("ZAP_DOCKER_IMAGE", "zaproxy/zap-stable:latest")
ZAP_MEMORY_LIMIT = os.getenv("ZAP_MEMORY_LIMIT", "1g")
ZAP_CPU_QUOTA = int(os.getenv("ZAP_CPU_QUOTA", "80000"))

ZAP_SCAN_PROFILES = {
    "baseline": {
        "description": "Baseline scan - rápido, sin autenticación",
        "command": "zap-baseline.py",
        "default_timeout": 120,
    },
    "full": {
        "description": "Full scan - completo, exploración profunda",
        "command": "zap-full-scan.py",
        "default_timeout": 600,
    },
    "api": {
        "description": "API scan - para APIs (OpenAPI, Swagger)",
        "command": "zap-api-scan.py",
        "default_timeout": 300,
    },
}


class ZAPRunner(BaseToolRunner):
    """Runner para OWASP ZAP (Zed Attack Proxy).

    Ejecuta escaneos de seguridad DAST (Dynamic Application Security Testing)
    sobre URLs usando la imagen oficial zaproxy/zap-stable en modo headless.

    Características:
    - Imagen Docker: zaproxy/zap-stable (oficial)
    - Modo Baseline: zap-baseline.py -t <URL> -J <archivo_salida>
    - Límites de recursos: memoria configurable (512m o 1g), CPU configurable
    - Parser de salida JSON/XML
    - Generación de fingerprints para retesting
    """

    def __init__(self):
        super().__init__(
            docker_image=ZAP_DOCKER_IMAGE,
            memory_limit=ZAP_MEMORY_LIMIT,
            cpu_quota=ZAP_CPU_QUOTA,
        )
        self._parser = ZAPParser()
        self._artifacts: list[str] = []

    def validate_input(self, params: dict) -> bool:
        """Valida los parámetros de entrada para ZAP.

        Args:
            params: Diccionario con los parámetros del job.

        Returns:
            True si los parámetros son válidos, False en caso contrario.
        """
        try:
            target = params.get("target", "")
            if not target:
                logger.error("zap_validation_failed", error="Target URL es requerida")
                return False

            parsed = urlparse(target)
            if not parsed.scheme:
                logger.error("zap_validation_failed", error=f"URL debe incluir esquema (http/https): {target}")
                return False
            if parsed.scheme not in ("http", "https"):
                logger.error("zap_validation_failed", error=f"ZAP solo soporta URLs HTTP/HTTPS: {target}")
                return False
            if not parsed.hostname:
                logger.error("zap_validation_failed", error=f"URL debe incluir hostname válido: {target}")
                return False

            valid_modes = list(ZAP_SCAN_PROFILES.keys())
            scan_mode = params.get("mode", "baseline")
            if scan_mode not in valid_modes:
                logger.error("zap_validation_failed", error=f"Modo inválido: {scan_mode}. Válidos: {valid_modes}")
                return False

            timeout = params.get("timeout", 300)
            if timeout < 60:
                logger.error("zap_validation_failed", error="Timeout mínimo para ZAP: 60 segundos")
                return False

            return True

        except Exception as e:
            logger.error("zap_validation_error", error=str(e))
            return False

    def build_command(self, params: dict) -> list[str]:
        """Construye el comando de ZAP según el modo seleccionado.

        Modo Baseline: zap-baseline.py -t <URL> -J <archivo_salida>

        Args:
            params: Diccionario con los parámetros del job.

        Returns:
            Lista de argumentos del comando.
        """
        scan_mode = params.get("mode", "baseline")
        profile = ZAP_SCAN_PROFILES[scan_mode]

        cmd = [profile["command"]]

        cmd.extend(["-t", params["target"]])

        cmd.extend(["-J", "/zap/wrk/report.json"])

        if scan_mode == "api":
            fmt = params.get("format", "openapi")
            cmd.extend(["-f", fmt])

        if scan_mode == "full":
            cmd.extend(["-j"])

        if params.get("spider"):
            max_duration = params["spider"]
            cmd.extend(["-d", str(max_duration)])

        if params.get("max_children"):
            cmd.extend(["-m", str(params["max_children"])])

        cmd.extend(["-x", "/zap/wrk/report.xml"])

        return cmd

    def collect_artifacts(self) -> list[str]:
        """Recupera los archivos creados por ZAP.

        Returns:
            Lista de rutas a los archivos de artefactos.
        """
        artifacts: list[str] = []

        zap_wrk_dir = Path("/tmp/aisec_artifacts/zap")
        if zap_wrk_dir.exists():
            for file in zap_wrk_dir.iterdir():
                if file.is_file():
                    artifacts.append(str(file))

        if not artifacts:
            self._artifacts_dir.mkdir(parents=True, exist_ok=True)
            for artifact_path in self._artifacts:
                if os.path.exists(artifact_path):
                    artifacts.append(artifact_path)

        return artifacts

    def parse_and_normalize(self, raw_output: str) -> list[FindingBase]:
        """Traduce el resultado de ZAP a la lista de hallazgos estándar.

        Args:
            raw_output: Salida cruda del escáner ZAP.

        Returns:
            Lista de hallazgos normalizados en formato FindingBase.
        """
        findings = self._parser.parse_json(raw_output)

        if not findings:
            findings = self._parser.parse_xml(raw_output)

        if not findings:
            findings = self._parser.parse_plain(raw_output)

        logger.info(
            "zap_parse_completed",
            total_findings=len(findings),
        )

        return findings

    def _save_artifact(
        self,
        content: str,
        filename: str,
        mime_type: str,
        artifact_type: str,
        params: dict,
    ) -> str | None:
        """Guarda un artefacto en disco.

        Returns:
            Ruta del archivo guardado o None si falla.
        """
        try:
            artifacts_dir = Path("/tmp/aisec_artifacts/zap")
            artifacts_dir.mkdir(parents=True, exist_ok=True)

            filepath = artifacts_dir / filename
            filepath.write_text(content, encoding="utf-8")

            self._artifacts.append(str(filepath))

            return str(filepath)
        except Exception as e:
            logger.warning("zap_save_artifact_failed", error=str(e))
            return None
