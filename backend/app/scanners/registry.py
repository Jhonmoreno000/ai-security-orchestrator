from typing import Type

from app.orchestrator.base_runner import BaseToolRunner
from app.scanners.zap_runner import ZAPRunner
from app.scanners.nuclei_runner import NucleiRunner
from app.scanners.semgrep_runner import SemgrepRunner
from app.scanners.trivy_runner import TrivyRunner
from app.schemas.runner import ToolType


SCANNER_REGISTRY: dict[ToolType, Type[BaseToolRunner]] = {
    ToolType.ZAP: ZAPRunner,
    ToolType.NUCLEI: NucleiRunner,
    ToolType.SEMGREP: SemgrepRunner,
    ToolType.TRIVY: TrivyRunner,
}


def get_runner(scanner_type: ToolType) -> Type[BaseToolRunner]:
    """Retorna la clase Runner para el tipo de escáner dado.

    Args:
        scanner_type: Tipo de escáner solicitado.

    Returns:
        La clase BaseToolRunner correspondiente.

    Raises:
        ValueError: Si el tipo de escáner no está registrado.
    """
    runner = SCANNER_REGISTRY.get(scanner_type)
    if runner is None:
        raise ValueError(f"Scanner type not registered: {scanner_type}")
    return runner


def list_available_scanners() -> list[ToolType]:
    """Retorna la lista de escáneres disponibles."""
    return list(SCANNER_REGISTRY.keys())
