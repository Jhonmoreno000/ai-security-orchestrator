from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

import structlog
from jinja2 import Environment, BaseLoader
from sqlalchemy.orm import Session

from app.models.entities import Finding, Scan, Project, Target, Retest
from app.reports.templates import REPORT_TEMPLATE

logger = structlog.get_logger()

SEVERITY_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}


class ReportGenerator:
    """Generador de reportes de seguridad en JSON, HTML y PDF."""

    def __init__(self, db: Session):
        self._db = db
        self._jinja_env = Environment(loader=BaseLoader(), autoescape=True)

    def export_json(self, scan_id: UUID) -> dict:
        scan = self._get_scan(scan_id)
        project = self._get_project(scan)
        target = self._get_target(scan)
        findings = self._get_findings(scan_id)
        retests = self._get_retests(scan_id)

        summary = self._build_summary(findings)
        owasp = self._build_owasp_breakdown(findings)
        cwe = self._build_cwe_breakdown(findings)
        ai_recs = self._extract_ai_recommendations(findings)

        report = {
            "report_type": "security_scan",
            "generated_at": datetime.utcnow().isoformat(),
            "project": {
                "id": str(project.id) if project else None,
                "name": project.name if project else "Unknown",
            },
            "scan": {
                "id": str(scan.id),
                "status": scan.status,
                "target_url": target.url if target else "Unknown",
                "target_label": target.label if target else None,
                "scanners": scan.scanners,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
            },
            "summary": summary,
            "owasp_top_10": owasp,
            "cwe_breakdown": cwe,
            "findings": [self._finding_to_dict(f) for f in findings],
            "retests": [self._retest_to_dict(r) for r in retests],
            "ai_recommendations": ai_recs,
        }

        logger.info("report_exported", format="json", scan_id=str(scan_id), findings=len(findings))
        return report

    def export_html(self, scan_id: UUID) -> str:
        scan = self._get_scan(scan_id)
        project = self._get_project(scan)
        target = self._get_target(scan)
        findings = self._get_findings(scan_id)

        summary = self._build_summary(findings)
        owasp = self._build_owasp_breakdown(findings)
        cwe = self._build_cwe_breakdown(findings)

        findings_data = []
        for f in findings:
            ai_summary = None
            if f.evidence and "[AI Analysis]" in (f.evidence or ""):
                parts = f.evidence.split("[AI Analysis]")
                if len(parts) > 1:
                    ai_summary = parts[1].strip()[:300]

            findings_data.append({
                "title": f.title,
                "description": f.description,
                "severity": f.severity,
                "scanner": f.scanner,
                "cwe": f.cwe,
                "url": f.url,
                "evidence": f.evidence,
                "remediation": f.remediation,
                "status": f.status,
                "ai_summary": ai_summary,
            })

        template = self._jinja_env.from_string(REPORT_TEMPLATE)
        html = template.render(
            title=f"Security Report - {target.url if target else 'Unknown'}",
            project_name=project.name if project else "Unknown",
            target_url=target.url if target else "Unknown",
            scan_id=str(scan.id),
            scan_status=scan.status,
            generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            summary=summary,
            owasp_breakdown=owasp,
            cwe_breakdown=cwe,
            findings=findings_data,
        )

        logger.info("report_exported", format="html", scan_id=str(scan_id), findings=len(findings))
        return html

    def export_pdf(self, scan_id: UUID) -> dict:
        html = self.export_html(scan_id)
        return {
            "html_content": html,
            "metadata": {
                "scan_id": str(scan_id),
                "format": "pdf",
                "generated_at": datetime.utcnow().isoformat(),
            },
        }

    def _get_scan(self, scan_id: UUID) -> Scan:
        scan = self._db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise ValueError(f"Scan not found: {scan_id}")
        return scan

    def _get_project(self, scan: Scan) -> Optional[Project]:
        try:
            return self._db.query(Project).filter(Project.id == scan.project_id).first()
        except Exception:
            return None

    def _get_target(self, scan: Scan) -> Optional[Target]:
        try:
            return self._db.query(Target).filter(Target.id == scan.target_id).first()
        except Exception:
            return None

    def _get_findings(self, scan_id: UUID) -> List[Finding]:
        return list(self._db.query(Finding).filter(Finding.scan_id == scan_id).all())

    def _get_retests(self, scan_id: UUID) -> List[Retest]:
        return list(self._db.query(Retest).filter(Retest.scan_id == scan_id).all())

    def _build_summary(self, findings: List[Finding]) -> dict:
        summary = {"total": len(findings), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "open": 0, "fixed": 0}
        for f in findings:
            sev = (f.severity or "").lower()
            if sev in summary:
                summary[sev] += 1
            if f.status == "OPEN":
                summary["open"] += 1
            elif f.status == "FIXED":
                summary["fixed"] += 1
        return summary

    def _build_owasp_breakdown(self, findings: List[Finding]) -> dict:
        breakdown: Dict[str, dict] = {}
        for f in findings:
            if not f.owasp:
                continue
            if f.owasp not in breakdown:
                breakdown[f.owasp] = {"count": 0, "titles": []}
            breakdown[f.owasp]["count"] += 1
            if f.title not in breakdown[f.owasp]["titles"]:
                breakdown[f.owasp]["titles"].append(f.title)
        return breakdown

    def _build_cwe_breakdown(self, findings: List[Finding]) -> dict:
        breakdown: Dict[str, dict] = {}
        for f in findings:
            if not f.cwe:
                continue
            if f.cwe not in breakdown:
                breakdown[f.cwe] = {"count": 0, "max_severity": "INFO", "findings": []}
            breakdown[f.cwe]["count"] += 1
            sev = (f.severity or "INFO").upper()
            if SEVERITY_ORDER.get(sev, 0) > SEVERITY_ORDER.get(breakdown[f.cwe]["max_severity"], 0):
                breakdown[f.cwe]["max_severity"] = sev
        return breakdown

    def _extract_ai_recommendations(self, findings: List[Finding]) -> List[dict]:
        recs = []
        for f in findings:
            if not f.remediation:
                continue
            recs.append({
                "finding_title": f.title,
                "severity": f.severity,
                "remediation": f.remediation[:500],
                "scanner": f.scanner,
            })
        return recs

    def _finding_to_dict(self, finding: Finding) -> dict:
        return {
            "id": str(finding.id),
            "title": finding.title,
            "description": finding.description,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "cwe": finding.cwe,
            "owasp": finding.owasp,
            "cvss_score": finding.cvss_score,
            "evidence": finding.evidence,
            "remediation": finding.remediation,
            "reference": finding.reference,
            "url": finding.url,
            "file_path": finding.file_path,
            "line_number": finding.line_number,
            "scanner": finding.scanner,
            "status": finding.status,
            "fingerprint": finding.fingerprint,
            "created_at": finding.created_at.isoformat() if finding.created_at else None,
        }

    def _retest_to_dict(self, retest: Retest) -> dict:
        return {
            "id": str(retest.id),
            "finding_id": str(retest.finding_id),
            "status": retest.status,
            "notes": retest.notes,
            "executed_at": retest.executed_at.isoformat() if retest.executed_at else None,
        }
