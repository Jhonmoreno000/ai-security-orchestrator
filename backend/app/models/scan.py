import uuid
from datetime import datetime

from sqlalchemy import (
    Column,
    DateTime,
    Enum,
    Float,
    Integer,
    String,
    Text,
    JSON,
    ForeignKey,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.db.base import Base


class Scan(Base):
    __tablename__ = "scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    target = Column(String(2048), nullable=False)
    status = Column(
        Enum("pending", "running", "completed", "failed", "cancelled", name="scan_status"),
        nullable=False,
        default="pending",
    )
    progress = Column(Float, default=0.0)
    options = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)

    results = relationship("ScanResult", back_populates="scan", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    scanner_type = Column(
        Enum("zap", "nuclei", "semgrep", "trivy", name="scanner_type"),
        nullable=False,
    )
    status = Column(
        Enum("pending", "running", "completed", "failed", "cancelled", name="result_status"),
        nullable=False,
        default="pending",
    )
    raw_output = Column(Text, nullable=True)
    errors = Column(JSON, default=list)
    duration_seconds = Column(Float, nullable=True)
    metadata = Column(JSON, default=dict)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)

    scan = relationship("Scan", back_populates="results")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(
        Enum("critical", "high", "medium", "low", "info", name="severity_level"),
        nullable=False,
    )
    scanner = Column(
        Enum("zap", "nuclei", "semgrep", "trivy", name="finding_scanner_type"),
        nullable=False,
    )
    cve = Column(String(50), nullable=True)
    cwe = Column(String(50), nullable=True)
    url = Column(String(2048), nullable=True)
    evidence = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    reference = Column(Text, nullable=True)
    cvss_score = Column(Float, nullable=True)
    confidence = Column(String(50), nullable=True)
    file_path = Column(String(1024), nullable=True)
    line_number = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    scan = relationship("Scan", back_populates="findings")
