from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any

import docker
import structlog
from docker.errors import ContainerError, ImageNotFound, APIError

from app.schemas.scanner import (
    Finding,
    ScanStatus,
    ScannerType,
    ToolConfig,
    ToolResult,
)

logger = structlog.get_logger()


class BaseToolRunner(ABC):
    """Clase abstracta base para todos los escáneres de seguridad.

    Cada escáner concreto debe implementar:
    - build_command(): Construye el comando específico del escáner.
    - parse_output(): Parsea la salida raw del contenedor a findings tipados.
    - get_image_name(): Retorna el nombre de la imagen Docker del escáner.
    """

    def __init__(self, config: ToolConfig):
        self.config = config
        self._client = docker.from_env()

    @property
    @abstractmethod
    def scanner_type(self) -> ScannerType:
        """Retorna el tipo de escáner."""
        ...

    @abstractmethod
    def get_image_name(self) -> str:
        """Retorna el nombre de la imagen Docker a utilizar."""
        ...

    @abstractmethod
    def build_command(self) -> list[str]:
        """Construye el comando a ejecutar dentro del contenedor."""
        ...

    @abstractmethod
    def parse_output(self, raw_output: str) -> list[Finding]:
        """Parsea la salida del escáner a una lista de Finding tipados."""
        ...

    def get_container_name(self) -> str:
        """Nombre del contenedor para tracking."""
        return f"scanner-{self.scanner_type.value}"

    async def run(self) -> ToolResult:
        """Ejecuta el escáner en un contenedor Docker aislado.

        Returns:
            ToolResult con el resultado del escaneo.

        Raises:
            RuntimeError: Si la imagen no existe o hay errores de Docker.
        """
        started_at = datetime.utcnow()
        logger.info(
            "scanner_started",
            scanner=self.scanner_type.value,
            target=self.config.target,
        )

        try:
            image_name = self.get_image_name()
            command = self.build_command()

            logger.info(
                "scanner_container_launching",
                image=image_name,
                command=command,
            )

            container = self._client.containers.run(
                image=image_name,
                command=command,
                name=self.get_container_name(),
                detach=True,
                remove=False,
                network_mode="bridge",
                mem_limit="512m",
                cpu_quota=50000,
                read_only=True,
                tmpfs={"/tmp": "size=100m"},
            )

            try:
                result = container.wait(timeout=self.config.timeout)
                raw_output = container.logs().decode("utf-8", errors="replace")

                if result.get("StatusCode", 1) != 0:
                    logger.warning(
                        "scanner_non_zero_exit",
                        scanner=self.scanner_type.value,
                        exit_code=result.get("StatusCode"),
                    )

                findings = self.parse_output(raw_output)
                finished_at = datetime.utcnow()
                duration = (finished_at - started_at).total_seconds()

                logger.info(
                    "scanner_completed",
                    scanner=self.scanner_type.value,
                    findings_count=len(findings),
                    duration=duration,
                )

                return ToolResult(
                    scanner=self.scanner_type,
                    status=ScanStatus.COMPLETED,
                    findings=findings,
                    raw_output=raw_output,
                    started_at=started_at,
                    finished_at=finished_at,
                    duration_seconds=duration,
                )

            finally:
                try:
                    container.remove(force=True)
                except Exception as e:
                    logger.warning("container_remove_failed", error=str(e))

        except ImageNotFound as e:
            logger.error("scanner_image_not_found", image=image_name, error=str(e))
            return ToolResult(
                scanner=self.scanner_type,
                status=ScanStatus.FAILED,
                errors=[f"Imagen no encontrada: {image_name}"],
                started_at=started_at,
                finished_at=datetime.utcnow(),
            )
        except APIError as e:
            logger.error("scanner_docker_api_error", scanner=self.scanner_type.value, error=str(e))
            return ToolResult(
                scanner=self.scanner_type,
                status=ScanStatus.FAILED,
                errors=[f"Error de Docker API: {str(e)}"],
                started_at=started_at,
                finished_at=datetime.utcnow(),
            )
        except Exception as e:
            logger.error("scanner_unexpected_error", scanner=self.scanner_type.value, error=str(e))
            return ToolResult(
                scanner=self.scanner_type,
                status=ScanStatus.FAILED,
                errors=[f"Error inesperado: {str(e)}"],
                started_at=started_at,
                finished_at=datetime.utcnow(),
            )
