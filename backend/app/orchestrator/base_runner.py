import hashlib
import os
import time
import uuid
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Any

import docker
import structlog
from docker.errors import ContainerError, ImageNotFound, APIError

from app.schemas.runner import FindingBase, ToolType

logger = structlog.get_logger()

ARTIFACTS_DIR = "/tmp/aisec_artifacts"
JOB_TIMEOUT = int(os.getenv("JOB_TIMEOUT", "300"))


class BaseToolRunner(ABC):
    """Clase abstracta base para todos los runners de herramientas de seguridad.

    Cada runner concreto debe implementar:
    - validate_input(): Validación específica de la herramienta
    - build_command(): Construcción del comando Docker
    - collect_artifacts(): Recolección de artefactos post-ejecución
    - parse_and_normalize(): Parseo y normalización de la salida a findings estándar

    El flujo de ejecución es:
    1. validate_input() → valida parámetros
    2. build_command() → construye comando
    3. execute() → ejecuta en contenedor Docker aislado
    4. collect_artifacts() → recoge artefactos
    5. parse_and_normalize() → parsea y normaliza findings
    """

    def __init__(self, docker_image: str, memory_limit: str = "512m", cpu_quota: int = 50000):
        self.docker_image = docker_image
        self.memory_limit = memory_limit
        self.cpu_quota = cpu_quota
        self._client: docker.DockerClient | None = None
        self._artifacts_dir = Path(ARTIFACTS_DIR) / str(uuid.uuid4())

    @property
    def client(self) -> docker.DockerClient:
        if self._client is None:
            self._client = docker.from_env()
        return self._client

    @abstractmethod
    def validate_input(self, params: dict) -> bool:
        """Valida los parámetros de entrada de la herramienta.

        Args:
            params: Diccionario con los parámetros del job.

        Returns:
            True si los parámetros son válidos, False en caso contrario.
        """
        ...

    @abstractmethod
    def build_command(self, params: dict) -> list[str]:
        """Construye el comando como lista de argumentos para prevenir inyecciones.

        Args:
            params: Diccionario con los parámetros del job.

        Returns:
            Lista de argumentos del comando.
        """
        ...

    def execute(self, command: list[str]) -> dict:
        """Ejecuta el contenedor Docker de la herramienta o subproceso aislado.

        Se ejecuta con límite de tiempo (JOB_TIMEOUT) y límites de recursos.

        Args:
            command: Lista de argumentos del comando a ejecutar.

        Returns:
            Diccionario con el resultado de la ejecución:
            {
                "exit_code": int,
                "stdout": str,
                "stderr": str,
                "duration_ms": int,
                "container_id": str | None,
                "timed_out": bool,
                "errors": list[str],
            }
        """
        result = {
            "exit_code": -1,
            "stdout": "",
            "stderr": "",
            "duration_ms": 0,
            "container_id": None,
            "timed_out": False,
            "errors": [],
        }

        start_time = time.monotonic()

        try:
            container = self.client.containers.run(
                image=self.docker_image,
                command=command,
                name=f"aisec-{uuid.uuid4().hex[:8]}",
                mem_limit=self.memory_limit,
                cpu_quota=self.cpu_quota,
                network_mode="bridge",
                read_only=True,
                tmpfs={"/tmp": "size=100m"},
                privileged=False,
                cap_drop=["ALL"],
                detach=True,
                remove=False,
            )

            result["container_id"] = container.id

            try:
                wait_result = container.wait(timeout=JOB_TIMEOUT)
                result["exit_code"] = wait_result.get("StatusCode", -1)
                result["stdout"] = container.logs(stdout=True, stderr=False).decode("utf-8", errors="replace")
                result["stderr"] = container.logs(stdout=False, stderr=True).decode("utf-8", errors="replace")
            except Exception as e:
                result["timed_out"] = True
                result["errors"].append(f"Timeout after {JOB_TIMEOUT}s: {str(e)}")
                result["exit_code"] = -1
            finally:
                try:
                    container.remove(force=True)
                except Exception as e:
                    result["errors"].append(f"Container remove failed: {str(e)}")

        except ImageNotFound as e:
            result["errors"].append(f"Docker image not found: {self.docker_image}")
        except APIError as e:
            result["errors"].append(f"Docker API error: {str(e)}")
        except Exception as e:
            result["errors"].append(f"Unexpected error: {str(e)}")

        result["duration_ms"] = int((time.monotonic() - start_time) * 1000)

        return result

    @abstractmethod
    def collect_artifacts(self) -> list[str]:
        """Recupera los archivos creados por el escáner (ej. results.json).

        Returns:
            Lista de rutas a los archivos de artefactos.
        """
        ...

    @abstractmethod
    def parse_and_normalize(self, raw_output: str) -> list[FindingBase]:
        """Traduce el resultado original a la lista de hallazgos estándar.

        Args:
            raw_output: Salida cruda del escáner.

        Returns:
            Lista de hallazgos normalizados en formato FindingBase.
        """
        ...

    def run(self, params: dict) -> dict:
        """Ejecuta el flujo completo de la herramienta de seguridad.

        Args:
            params: Parámetros del job de escaneo.

        Returns:
            Diccionario con el resultado completo incluyendo findings y artefactos.
        """
        started_at = datetime.utcnow()
        start_time = time.monotonic()

        logger.info(
            "tool_execution_started",
            tool=self.__class__.__name__,
            target=params.get("target"),
        )

        if not self.validate_input(params):
            return {
                "status": "failed",
                "exit_code": -1,
                "duration_ms": int((time.monotonic() - start_time) * 1000),
                "errors": ["Input validation failed"],
                "findings": [],
                "artifacts": [],
                "started_at": started_at.isoformat(),
                "finished_at": datetime.utcnow().isoformat(),
            }

        command = self.build_command(params)
        logger.info("tool_command_built", command=command)

        exec_result = self.execute(command)

        artifacts = self.collect_artifacts()
        findings = self.parse_and_normalize(exec_result.get("stdout", ""))

        finished_at = datetime.utcnow()
        duration_ms = int((time.monotonic() - start_time) * 1000)

        status = "completed" if exec_result["exit_code"] == 0 else "failed"

        logger.info(
            "tool_execution_completed",
            tool=self.__class__.__name__,
            exit_code=exec_result["exit_code"],
            findings_count=len(findings),
            artifacts_count=len(artifacts),
            duration_ms=duration_ms,
        )

        findings_dicts = []
        for f in findings:
            if hasattr(f, "model_dump"):
                findings_dicts.append(f.model_dump())
            elif hasattr(f, "dict"):
                findings_dicts.append(f.dict())
            else:
                findings_dicts.append(f)

        return {
            "status": status,
            "exit_code": exec_result["exit_code"],
            "duration_ms": duration_ms,
            "stdout": exec_result.get("stdout", ""),
            "stderr": exec_result.get("stderr", ""),
            "timed_out": exec_result.get("timed_out", False),
            "errors": exec_result.get("errors", []),
            "findings": findings_dicts,
            "artifacts": artifacts,
            "started_at": started_at.isoformat(),
            "finished_at": finished_at.isoformat(),
        }

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
