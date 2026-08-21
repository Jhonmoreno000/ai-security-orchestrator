import json
from typing import List, Optional
from uuid import UUID

import structlog
from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.models.entities import Finding
from app.schemas.runner import FindingBase

logger = structlog.get_logger()


def _serialize_evidence(evidence) -> str:
    """Serializa evidence a string para almacenamiento en TEXT."""
    if evidence is None:
        return None
    if isinstance(evidence, str):
        return evidence
    return json.dumps(evidence, ensure_ascii=False)


def persist_findings(
    db: Session,
    scan_id: UUID,
    findings: List[FindingBase],
) -> dict:
    """Persiste findings correlacionados en la tabla findings.

    Para cada finding:
    - Si ya existe un registro con el mismo fingerprint para este scan_id,
      actualiza los campos (upsert by fingerprint + scan_id).
    - Si no existe, inserta un nuevo registro.

    Args:
        db: Sesion de SQLAlchemy activa.
        scan_id: ID del scan al que pertenecen los findings.
        findings: Lista de FindingBase correlacionados y deduplicados.

    Returns:
        Dict con estadisticas: inserted, updated, total.
    """
    stats = {"inserted": 0, "updated": 0, "total": len(findings)}

    for finding in findings:
        try:
            existing = _find_existing(db, scan_id, finding.fingerprint)

            if existing:
                _update_finding(db, existing, finding)
                stats["updated"] += 1
                logger.info(
                    "finding_updated",
                    finding_id=str(existing.id),
                    fingerprint=finding.fingerprint,
                    scanner=finding.scanner,
                )
            else:
                _insert_finding(db, scan_id, finding)
                stats["inserted"] += 1
                logger.info(
                    "finding_inserted",
                    fingerprint=finding.fingerprint,
                    scanner=finding.scanner,
                )
        except Exception as e:
            logger.error(
                "finding_persist_error",
                fingerprint=finding.fingerprint,
                error=str(e),
            )
            raise

    db.commit()

    logger.info(
        "findings_persisted",
        scan_id=str(scan_id),
        inserted=stats["inserted"],
        updated=stats["updated"],
        total=stats["total"],
    )

    return stats


def _find_existing(
    db: Session,
    scan_id: UUID,
    fingerprint: Optional[str],
) -> Optional[Finding]:
    """Busca un finding existente por scan_id + fingerprint."""
    if not fingerprint:
        return None

    stmt = select(Finding).where(
        Finding.scan_id == scan_id,
        Finding.fingerprint == fingerprint,
    ).limit(1)

    return db.execute(stmt).scalar_one_or_none()


def _insert_finding(
    db: Session,
    scan_id: UUID,
    finding: FindingBase,
) -> Finding:
    """Inserta un nuevo finding en la base de datos."""
    db_finding = Finding(
        scan_id=scan_id,
        title=finding.title,
        description=finding.description,
        severity=finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
        confidence=finding.confidence,
        cwe=finding.cwe,
        owasp=finding.owasp,
        cvss_score=finding.cvss_score,
        evidence=_serialize_evidence(finding.evidence),
        remediation=finding.remediation,
        reference=finding.reference,
        url=finding.url,
        file_path=finding.file_path,
        line_number=finding.line_number,
        status=finding.status.value if hasattr(finding.status, "value") else str(finding.status),
        fingerprint=finding.fingerprint,
        scanner=finding.scanner.value if hasattr(finding.scanner, "value") else str(finding.scanner),
        raw_id=finding.raw_id,
        metadata=finding.metadata,
    )
    db.add(db_finding)
    db.flush()
    return db_finding


def _update_finding(
    db: Session,
    db_finding: Finding,
    finding: FindingBase,
) -> Finding:
    """Actualiza un finding existente con los datos nuevos."""
    db_finding.title = finding.title
    db_finding.description = finding.description
    db_finding.severity = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
    db_finding.confidence = finding.confidence
    db_finding.cwe = finding.cwe
    db_finding.owasp = finding.owasp
    db_finding.cvss_score = finding.cvss_score
    db_finding.evidence = _serialize_evidence(finding.evidence)
    db_finding.remediation = finding.remediation
    db_finding.reference = finding.reference
    db_finding.url = finding.url
    db_finding.file_path = finding.file_path
    db_finding.line_number = finding.line_number
    db_finding.status = finding.status.value if hasattr(finding.status, "value") else str(finding.status)
    db_finding.fingerprint = finding.fingerprint
    db_finding.scanner = finding.scanner.value if hasattr(finding.scanner, "value") else str(finding.scanner)
    db_finding.raw_id = finding.raw_id
    db_finding.metadata = finding.metadata
    db.flush()
    return db_finding


def get_findings_by_scan(
    db: Session,
    scan_id: UUID,
    severity: Optional[str] = None,
    scanner: Optional[str] = None,
) -> List[Finding]:
    """Obtiene todos los findings de un scan con filtros opcionales."""
    stmt = select(Finding).where(Finding.scan_id == scan_id)

    if severity:
        stmt = stmt.where(Finding.severity == severity.upper())
    if scanner:
        stmt = stmt.where(Finding.scanner == scanner.lower())

    stmt = stmt.order_by(Finding.created_at.desc())
    return list(db.execute(stmt).scalars().all())


def get_finding_by_id(
    db: Session,
    finding_id: UUID,
) -> Optional[Finding]:
    """Obtiene un finding por su ID."""
    stmt = select(Finding).where(Finding.id == finding_id)
    return db.execute(stmt).scalar_one_or_none()
