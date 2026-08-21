from app.orchestrator.base_runner import BaseToolRunner
from app.scanners.zap_runner import ZAPRunner
from app.scanners.nuclei_runner import NucleiRunner
from app.scanners.semgrep_runner import SemgrepRunner
from app.scanners.trivy_runner import TrivyRunner
from app.schemas.runner import ToolType

RUNNER_MAP: dict[ToolType, type[BaseToolRunner]] = {
    ToolType.ZAP: ZAPRunner,
    ToolType.NUCLEI: NucleiRunner,
    ToolType.SEMGREP: SemgrepRunner,
    ToolType.TRIVY: TrivyRunner,
}

KNOWN_TOOLS = [t.value for t in ToolType]


def create_runner(tool: str | ToolType) -> BaseToolRunner:
    """Retorna una instancia del runner correspondiente a la herramienta solicitada.

    Args:
        tool: Nombre de la herramienta (str) o ToolType enum.

    Returns:
        Instancia de BaseToolRunner inicializada.

    Raises:
        ValueError: Si la herramienta no está registrada.
    """
    if isinstance(tool, str):
        try:
            tool_type = ToolType(tool.lower())
        except ValueError:
            raise ValueError(
                f"Unknown tool: '{tool}'. Available tools: {KNOWN_TOOLS}"
            )
    else:
        tool_type = tool

    runner_cls = RUNNER_MAP.get(tool_type)
    if runner_cls is None:
        raise ValueError(
            f"No runner registered for tool: {tool_type}. Available: {KNOWN_TOOLS}"
        )

    return runner_cls()
