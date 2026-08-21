from datetime import datetime
from typing import List, Optional
from uuid import UUID

import structlog
from sqlalchemy.orm import Session

from app.models.entities import Finding, Retest, Scan
from app.orchestrator.runner_factory import create_runner
from app.schemas.retest import RetestRequest, RetestResult, RetestStatus

logger = structlog.get_logger()


class RetestEngine:
    """Motor de retest para validar si una correccion fue efectiva.

    Flujo:
    1. Recupera el hallazgo por fingerprint con estado OPEN
    2. Reejecuta la herramienta origen sobre el endpoint especifico
    3. Compara fingerprints BEFORE vs AFTER
    4. Actualiza estado: FIXED, STILL_PRESENT o INCONCLUSIVE
    """

    def __init__(self, db: Session):
        self._db = db

    async def retest(self, request: RetestRequest) -> RetestResult:
        """Ejecuta un retest para un finding individual.

        Args:
            request: Solicitud con finding_id, fingerprint, source_tool y endpoint.

        Returns:
            RetestResult con el resultado de la comparacion.
        """
        started_at = datetime.utcnow()
        retest_record = self._create_retest_record(request)

        try:
            finding = self._get_finding(request)
            if finding is None:
                return self._build_error_result(
                    request, retest_record, "Finding not found"
                )

            original_status = finding.status

            logger.info(
                "retest_started",
                finding_id=str(request.finding_id),
                fingerprint=request.fingerprint,
                source_tool=request.source_tool,
                endpoint=request.endpoint,
            )

            scan_result = await self._execute_scan(request)

            if scan_result.get("timed_out"):
                return self._build_inconclusive(
                    request, retest_record, original_status,
                    "Scan timed out", scan_result
                )

            if scan_result.get("errors"):
                return self._build_inconclusive(
                    request, retest_record, original_status,
                    f"Scan errors: {scan_result['errors']}", scan_result
                )

            fingerprints_after = self._extract_fingerprints(scan_result)

            if request.fingerprint in fingerprints_after:
                return self._build_still_present(
                    request, retest_record, original_status,
                    fingerprints_after, scan_result
                )
            else:
                return self._build_fixed(
                    request, retest_record, original_status,
                    fingerprints_after, scan_result
                )

        except Exception as e:
            logger.error("retest_error", finding_id=str(request.finding_id), error=str(e))
            return self._build_error_result(
                request, retest_record, str(e)
            )

    def _get_finding(self, request: RetestRequest) -> Optional[Finding]:
        """Recupera el finding por ID."""
        return self._db.query(Finding).filter(
            Finding.id == request.finding_id
        ).first()

    def _create_retest_record(self, request: RetestRequest) -> Retest:
        """Crea un registro Retest en la BD."""
        retest = Retest(
            finding_id=request.finding_id,
            scan_id=request.scan_id,
            status="RUNNING",
        )
        self._db.add(retest)
        self._db.commit()
        self._db.refresh(retest)
        return retest

    async def _execute_scan(self, request: RetestRequest) -> dict:
        """Ejecuta la herramienta origen sobre el endpoint."""
        runner = create_runner(request.source_tool)

        params = {
            "target": request.endpoint,
            "timeout": 120,
            "options": {},
        }

        return runner.run(params)

    def _extract_fingerprints(self, scan_result: dict) -> List[str]:
        """Extrae fingerprints de los findings del escaneo."""
        fingerprints = []
        for finding in scan_result.get("findings", []):
            fp = finding.get("fingerprint")
            if fp:
                fingerprints.append(fp)
        return fingerprints

    def _build_fixed(
        self,
        request: RetestRequest,
        retest_record: Retest,
        original_status: str,
        fingerprints_after: List[str],
        scan_result: dict,
    ) -> RetestResult:
        """Construye resultado FIXED."""
        self._update_retest_and_finding(
            retest_record,
            request.finding_id,
            "FIXED",
            f"Vulnerability fixed. Fingerprint {request.fingerprint} no longer present.",
        )

        return RetestResult(
            retest_id=retest_record.id,
            finding_id=request.finding_id,
            previous_status=original_status,
            new_status=RetestStatus.FIXED,
            fingerprints_before=[request.fingerprint],
            fingerprints_after=fingerprints_after,
            notes="Fingerprint not found in new scan. Vulnerability appears fixed.",
            duration_ms=scan_result.get("duration_ms", 0),
            metadata={
                "exit_code": scan_result.get("exit_code"),
                "findings_count": len(scan_result.get("findings", [])),
            },
        )

    def _build_still_present(
        self,
        request: RetestRequest,
        retest_record: Retest,
        original_status: str,
        fingerprints_after: List[str],
        scan_result: dict,
    ) -> RetestResult:
        """Construye resultado STILL_PRESENT."""
        self._update_retest_and_finding(
            retest_record,
            request.finding_id,
            "STILL_PRESENT",
            f"Vulnerability still present. Fingerprint {request.fingerprint} found again.",
        )

        return RetestResult(
            retest_id=retest_record.id,
            finding_id=request.finding_id,
            previous_status=original_status,
            new_status=RetestStatus.STILL_PRESENT,
            fingerprints_before=[request.fingerprint],
            fingerprints_after=fingerprints_after,
            notes="Fingerprint still present in new scan. Vulnerability not fixed.",
            duration_ms=scan_result.get("duration_ms", 0),
            metadata={
                "exit_code": scan_result.get("exit_code"),
                "findings_count": len(scan_result.get("findings", [])),
            },
        )

    def _build_inconclusive(
        self,
        request: RetestRequest,
        retest_record: Retest,
        original_status: str,
        reason: str,
        scan_result: dict,
    ) -> RetestResult:
        """Construye resultado INCONCLUSIVE."""
        self._update_retest_status(retest_record, "INCONCLUSIVE", reason)

        return RetestResult(
            retest_id=retest_record.id,
            finding_id=request.finding_id,
            previous_status=original_status,
            new_status=RetestStatus.INCONCLUSIVE,
            fingerprints_before=[request.fingerprint],
            notes=reason,
            duration_ms=scan_result.get("duration_ms", 0),
            errors=scan_result.get("errors", []),
        )

    def _build_error_result(
        self,
        request: RetestRequest,
        retest_record: Retest,
        error_msg: str,
    ) -> RetestResult:
        """Construye resultado de error."""
        self._update_retest_status(retest_record, "ERROR", error_msg)

        return RetestResult(
            retest_id=retest_record.id,
            finding_id=request.finding_id,
            previous_status="UNKNOWN",
            new_status=RetestStatus.ERROR,
            fingerprints_before=[request.fingerprint],
            notes=error_msg,
            errors=[error_msg],
        )

    def _update_retest_and_finding(
        self,
        retest_record: Retest,
        finding_id: UUID,
        status: str,
        notes: str,
    ) -> None:
        """Actualiza el registro Retest y el Finding."""
        retest_record.status = status
        retest_record.notes = notes
        retest_record.executed_at = datetime.utcnow()

        finding = self._db.query(Finding).filter(Finding.id == finding_id).first()
        if finding:
            if status == "FIXED":
                finding.status = "FIXED"
            elif status == "STILL_PRESENT":
                finding.status = "STILL_PRESENT"

        self._db.commit()

    def _update_retest_status(
        self,
        retest_record: Retest,
        status: str,
        notes: str,
    ) -> None:
        """Actualiza solo el estado del Retest."""
        retest_record.status = status
        retest_record.notes = notes
        retest_record.executed_at = datetime.utcnow()
        self._db.commit()
