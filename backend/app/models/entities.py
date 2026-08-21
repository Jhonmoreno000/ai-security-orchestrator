import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    JSON,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.db.base import Base


class Project(Base):
    __tablename__ = "projects"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False, unique=True)
    description = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    targets = relationship("Target", back_populates="project", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="project", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="project", cascade="all, delete-orphan")


class Target(Base):
    __tablename__ = "targets"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id"), nullable=False)
    url = Column(String(2048), nullable=False)
    label = Column(String(255), nullable=True)
    target_type = Column(String(50), nullable=False, default="url")
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    project = relationship("Project", back_populates="targets")
    scans = relationship("Scan", back_populates="target", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    target_id = Column(UUID(as_uuid=True), ForeignKey("targets.id"), nullable=False)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id"), nullable=False)
    scanners = Column(JSON, nullable=False)
    options = Column(JSON, default=dict)
    timeout = Column(Integer, default=300)
    status = Column(
        Enum("PENDING", "QUEUED", "RUNNING", "COMPLETED", "FAILED", "CANCELLED", name="scan_status"),
        nullable=False,
        default="PENDING",
    )
    progress = Column(Float, default=0.0)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    target = relationship("Target", back_populates="scans")
    project = relationship("Project", back_populates="scans")
    jobs = relationship("Job", back_populates="scan", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    artifacts = relationship("Artifact", back_populates="scan", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="scan")
    retests = relationship("Retest", back_populates="scan", cascade="all, delete-orphan")


class Job(Base):
    __tablename__ = "jobs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    scanner_type = Column(
        Enum("zap", "nuclei", "semgrep", "trivy", name="scanner_type_enum"),
        nullable=False,
    )
    target_url = Column(String(2048), nullable=False)
    config = Column(JSON, default=dict)
    priority = Column(Integer, default=0)
    status = Column(
        Enum("PENDING", "RUNNING", "COMPLETED", "FAILED", "RETRYING", name="job_status"),
        nullable=False,
        default="PENDING",
    )
    result = Column(JSON, nullable=True)
    error_message = Column(Text, nullable=True)
    retry_count = Column(Integer, default=0)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    scan = relationship("Scan", back_populates="jobs")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    job_id = Column(UUID(as_uuid=True), ForeignKey("jobs.id"), nullable=True)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(
        Enum("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", name="severity_level"),
        nullable=False,
    )
    confidence = Column(String(50), nullable=False)
    cwe = Column(String(50), nullable=True)
    owasp = Column(String(100), nullable=True)
    evidence = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    status = Column(
        Enum("OPEN", "FIXED", "STILL_PRESENT", name="finding_status"),
        nullable=False,
        default="OPEN",
    )
    fingerprint = Column(String(255), nullable=True)
    cvss_score = Column(Float, nullable=True)
    url = Column(String(2048), nullable=True)
    file_path = Column(String(1024), nullable=True)
    line_number = Column(Integer, nullable=True)
    scanner = Column(
        Enum("zap", "nuclei", "semgrep", "trivy", name="finding_scanner_enum"),
        nullable=False,
    )
    reference = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    scan = relationship("Scan", back_populates="findings")
    job = relationship("Job")
    artifacts = relationship("Artifact", back_populates="finding", cascade="all, delete-orphan")
    retests = relationship("Retest", back_populates="finding", cascade="all, delete-orphan")


class Artifact(Base):
    __tablename__ = "artifacts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    finding_id = Column(UUID(as_uuid=True), ForeignKey("findings.id"), nullable=True)
    artifact_type = Column(String(50), nullable=False)
    filename = Column(String(255), nullable=False)
    mime_type = Column(String(100), nullable=True)
    size_bytes = Column(Integer, nullable=True)
    storage_path = Column(String(1024), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    scan = relationship("Scan", back_populates="artifacts")
    finding = relationship("Finding", back_populates="artifacts")


class Report(Base):
    __tablename__ = "reports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id"), nullable=False)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=True)
    title = Column(String(255), nullable=False)
    format = Column(
        Enum("json", "html", "pdf", "sarif", name="report_format"),
        nullable=False,
        default="json",
    )
    is_public = Column(Boolean, default=False)
    file_path = Column(String(1024), nullable=True)
    generated_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    project = relationship("Project", back_populates="reports")
    scan = relationship("Scan", back_populates="reports")


class Retest(Base):
    __tablename__ = "retests"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    finding_id = Column(UUID(as_uuid=True), ForeignKey("findings.id"), nullable=False)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    status = Column(
        Enum("PENDING", "RUNNING", "FIXED", "STILL_PRESENT", "ERROR", name="retest_status"),
        nullable=False,
        default="PENDING",
    )
    notes = Column(Text, nullable=True)
    executed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    finding = relationship("Finding", back_populates="retests")
    scan = relationship("Scan", back_populates="retests")
