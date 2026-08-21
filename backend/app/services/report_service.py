import json
from datetime import datetime
from typing import Any, List, Optional
from uuid import UUID

import structlog
from sqlalchemy.orm import Session

from app.models.entities import Finding, Scan, Project, Target

logger = structlog.get_logger()


class ReportService:
    """Servicio de generacion de reportes en HTML, PDF y JSON."""

    def __init__(self, db: Session):
        self._db = db

    def generate_json(self, scan_id: UUID) -> dict:
        """Genera reporte en formato JSON.

        Args:
            scan_id: ID del scan a reportar.

        Returns:
            Dict con el reporte completo.
        """
        scan = self._db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise ValueError(f"Scan not found: {scan_id}")

        findings = self._db.query(Finding).filter(
            Finding.scan_id == scan_id
        ).all()

        report = {
            "report_type": "security_scan",
            "generated_at": datetime.utcnow().isoformat(),
            "scan": {
                "id": str(scan.id),
                "status": scan.status,
                "target": self._get_target_url(scan),
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
            },
            "summary": self._build_summary(findings),
            "findings": [self._finding_to_dict(f) for f in findings],
        }

        logger.info("report_generated", format="json", scan_id=str(scan_id), findings=len(findings))
        return report

    def generate_html(self, scan_id: UUID) -> str:
        """Genera reporte en formato HTML.

        Args:
            scan_id: ID del scan a reportar.

        Returns:
            String con el HTML completo del reporte.
        """
        scan = self._db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise ValueError(f"Scan not found: {scan_id}")

        findings = self._db.query(Finding).filter(
            Finding.scan_id == scan_id
        ).all()

        summary = self._build_summary(findings)
        target_url = self._get_target_url(scan)

        findings_html = "\n".join(
            self._finding_to_html(f) for f in findings
        )

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Report - {target_url}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; color: #333; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: white; padding: 40px; border-radius: 12px; margin-bottom: 30px; }}
        .header h1 {{ font-size: 28px; margin-bottom: 10px; }}
        .header p {{ opacity: 0.8; font-size: 14px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .summary-card {{ background: white; padding: 25px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.08); text-align: center; }}
        .summary-card h3 {{ font-size: 36px; margin-bottom: 5px; }}
        .summary-card p {{ color: #666; font-size: 13px; text-transform: uppercase; }}
        .critical {{ color: #dc3545; }}
        .high {{ color: #fd7e14; }}
        .medium {{ color: #ffc107; }}
        .low {{ color: #28a745; }}
        .info {{ color: #17a2b8; }}
        .findings {{ margin-top: 30px; }}
        .finding {{ background: white; border-radius: 10px; padding: 25px; margin-bottom: 15px; box-shadow: 0 2px 10px rgba(0,0,0,0.08); border-left: 4px solid #ddd; }}
        .finding.critical {{ border-left-color: #dc3545; }}
        .finding.high {{ border-left-color: #fd7e14; }}
        .finding.medium {{ border-left-color: #ffc107; }}
        .finding.low {{ border-left-color: #28a745; }}
        .finding.info {{ border-left-color: #17a2b8; }}
        .finding h4 {{ font-size: 18px; margin-bottom: 10px; }}
        .finding-meta {{ display: flex; gap: 15px; margin-bottom: 10px; flex-wrap: wrap; }}
        .badge {{ padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; text-transform: uppercase; }}
        .badge.severity {{ background: #e9ecef; }}
        .finding p {{ color: #555; font-size: 14px; }}
        .finding pre {{ background: #f8f9fa; padding: 15px; border-radius: 6px; margin-top: 10px; overflow-x: auto; font-size: 13px; }}
        .footer {{ text-align: center; padding: 30px; color: #888; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Security Scan Report</h1>
            <p>Target: {target_url}</p>
            <p>Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
            <p>Status: {scan.status}</p>
        </div>

        <div class="summary">
            <div class="summary-card">
                <h3 class="critical">{summary['critical']}</h3>
                <p>Critical</p>
            </div>
            <div class="summary-card">
                <h3 class="high">{summary['high']}</h3>
                <p>High</p>
            </div>
            <div class="summary-card">
                <h3 class="medium">{summary['medium']}</h3>
                <p>Medium</p>
            </div>
            <div class="summary-card">
                <h3 class="low">{summary['low']}</h3>
                <p>Low</p>
            </div>
            <div class="summary-card">
                <h3 class="info">{summary['info']}</h3>
                <p>Info</p>
            </div>
            <div class="summary-card">
                <h3>{summary['total']}</h3>
                <p>Total</p>
            </div>
        </div>

        <div class="findings">
            <h2 style="margin-bottom: 20px;">Findings ({summary['total']})</h2>
            {findings_html}
        </div>

        <div class="footer">
            <p>Generated by AI Security Orchestrator</p>
        </div>
    </div>
</body>
</html>"""

        logger.info("report_generated", format="html", scan_id=str(scan_id), findings=len(findings))
        return html

    def generate_pdf_content(self, scan_id: UUID) -> dict:
        """Genera datos para PDF (HTML renderizable).

        Args:
            scan_id: ID del scan a reportar.

        Returns:
            Dict con html_content y metadata.
        """
        html_content = self.generate_html(scan_id)
        scan = self._db.query(Scan).filter(Scan.id == scan_id).first()

        return {
            "html_content": html_content,
            "metadata": {
                "scan_id": str(scan_id),
                "format": "pdf",
                "generated_at": datetime.utcnow().isoformat(),
                "page_title": f"Security Report - {self._get_target_url(scan)}",
            },
        }

    def _build_summary(self, findings: List[Finding]) -> dict:
        """Construye resumen de severidad."""
        summary = {
            "total": len(findings),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "open": 0,
            "fixed": 0,
        }

        for f in findings:
            sev = (f.severity or "").lower()
            if sev in summary:
                summary[sev] += 1

            if f.status == "OPEN":
                summary["open"] += 1
            elif f.status == "FIXED":
                summary["fixed"] += 1

        return summary

    def _get_target_url(self, scan: Scan) -> str:
        """Obtiene la URL del target del scan."""
        try:
            target = self._db.query(Target).filter(Target.id == scan.target_id).first()
            if target:
                return target.url
        except Exception:
            pass
        return "Unknown"

    def _finding_to_dict(self, finding: Finding) -> dict:
        """Convierte un Finding a dict."""
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

    def _finding_to_html(self, finding: Finding) -> str:
        """Convierte un Finding a bloque HTML."""
        severity = (finding.severity or "info").lower()
        status_badge = ""
        if finding.status == "FIXED":
            status_badge = '<span class="badge" style="background:#d4edda;color:#155724;">FIXED</span>'
        elif finding.status == "STILL_PRESENT":
            status_badge = '<span class="badge" style="background:#f8d7da;color:#721c24;">STILL PRESENT</span>'

        evidence_section = ""
        if finding.evidence:
            evidence = finding.evidence
            if len(evidence) > 500:
                evidence = evidence[:500] + "..."
            evidence_section = f"<p><strong>Evidence:</strong></p><pre>{evidence}</pre>"

        remediation_section = ""
        if finding.remediation:
            remediation = finding.remediation
            if len(remediation) > 500:
                remediation = remediation[:500] + "..."
            remediation_section = f"<p><strong>Remediation:</strong></p><pre>{remediation}</pre>"

        return f"""
        <div class="finding {severity}">
            <h4>{finding.title}</h4>
            <div class="finding-meta">
                <span class="badge severity">{finding.severity}</span>
                <span class="badge" style="background:#e9ecef;">{finding.scanner}</span>
                {f'<span class="badge" style="background:#e9ecef;">{finding.cwe}</span>' if finding.cwe else ''}
                {status_badge}
            </div>
            <p>{finding.description or 'No description available.'}</p>
            {evidence_section}
            {remediation_section}
        </div>
        """
