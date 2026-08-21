import hashlib
import re
from typing import Optional

from app.schemas.runner import ToolType


def _normalize(value: Optional[str]) -> str:
    """Normaliza un valor para fingerprint: lowercase, strip, espacios multiples → 1."""
    if value is None:
        return ""
    normalized = value.strip().lower()
    normalized = re.sub(r"\s+", " ", normalized)
    return normalized


def _normalize_title(title: Optional[str]) -> str:
    """Extrae la parte clave del title para fingerprint DAST.

    Elimina números de versión, IDs y tokens irrelevantes.
    """
    if title is None:
        return ""
    normalized = _normalize(title)
    normalized = re.sub(r"\b\d+\b", "", normalized)
    normalized = re.sub(r"[^a-z0-9\s]", "", normalized)
    normalized = re.sub(r"\s+", " ", normalized).strip()
    return normalized


def _normalize_cwe(cwe: Optional[str]) -> str:
    """Extrae solo el número del CWE si es posible.

    Ejemplos: 'CWE-79' → '79', 'cwe 79' → '79', '79' → '79'
    """
    if cwe is None:
        return ""
    match = re.search(r"(\d+)", cwe)
    return match.group(1) if match else _normalize(cwe)


def generate_fingerprint(
    *,
    tool_type: ToolType,
    title: Optional[str] = None,
    endpoint: Optional[str] = None,
    cwe: Optional[str] = None,
    category: Optional[str] = None,
    file_path: Optional[str] = None,
    line_number: Optional[int] = None,
    vulnerability_id: Optional[str] = None,
    package_name: Optional[str] = None,
) -> str:
    """Genera un fingerprint SHA-256 estable e inmutable para un hallazgo.

    DAST (ZAP / Nuclei):
        SHA256(endpoint + cwe/category + title_key_part)

    SAST / SBOM (Semgrep / Trivy):
        SHA256(file_path + cwe/vulnerability_id + line_number/package_name)

    Args:
        tool_type: Tipo de herramienta (ZAP, NUCLEI, SEMGREP, TRIVY).
        title: Título del hallazgo (DAST).
        endpoint: URL o host del hallazgo (DAST).
        cwe: CWE ID (ej: CWE-79).
        category: Categoría alternativa al CWE (DAST).
        file_path: Ruta del archivo (SAST/SBOM).
        line_number: Número de línea (SAST).
        vulnerability_id: ID de vulnerabilidad como CVE (SBOM).
        package_name: Nombre del paquete (SBOM).

    Returns:
        Hash SHA-256 de 64 caracteres en hex.
    """
    if tool_type in (ToolType.ZAP, ToolType.NUCLEI):
        parts = [
            _normalize(endpoint),
            _normalize_cwe(cwe) or _normalize(category),
            _normalize_title(title),
        ]
    else:
        parts = [
            _normalize(file_path),
            _normalize_cwe(cwe) or _normalize(vulnerability_id),
            str(line_number) if line_number is not None else "",
            _normalize(package_name),
        ]

    composite = "|".join(parts)
    return hashlib.sha256(composite.encode("utf-8")).hexdigest()


def generate_fingerprint_from_dict(finding: dict) -> str:
    """Genera fingerprint desde un dict de finding normalizado.

    Extrae los campos necesarios según el scanner declarado.
    """
    scanner = finding.get("scanner", "")

    tool_type_map = {
        "zap": ToolType.ZAP,
        "nuclei": ToolType.NUCLEI,
        "semgrep": ToolType.SEMGREP,
        "trivy": ToolType.TRIVY,
    }

    tool_type = tool_type_map.get(scanner)
    if tool_type is None:
        return hashlib.sha256(str(finding).encode("utf-8")).hexdigest()[:32]

    return generate_fingerprint(
        tool_type=tool_type,
        title=finding.get("title"),
        endpoint=finding.get("url") or finding.get("endpoint"),
        cwe=finding.get("cwe"),
        category=finding.get("category"),
        file_path=finding.get("file_path"),
        line_number=finding.get("line_number"),
        vulnerability_id=finding.get("raw_id") or finding.get("vulnerability_id"),
        package_name=finding.get("package_name")
            or finding.get("metadata", {}).get("trivy_pkg"),
    )
