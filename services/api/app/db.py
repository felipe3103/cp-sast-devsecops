"""Persistência: SQLAlchemy 2.x (PostgreSQL em produção, SQLite em dev/testes)."""
from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

from .config import settings


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Project(Base):
    __tablename__ = "projects"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    scans: Mapped[list["Scan"]] = relationship(back_populates="project", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), index=True)
    status: Mapped[str] = mapped_column(String(20), default="queued")  # queued|running|completed|failed
    source: Mapped[str] = mapped_column(String(20))                    # upload|git|ci|snippet
    ref: Mapped[str] = mapped_column(String(300), default="")          # repo/branch/commit
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    files_scanned: Mapped[int] = mapped_column(Integer, default=0)
    lines_scanned: Mapped[int] = mapped_column(Integer, default=0)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    counts: Mapped[dict] = mapped_column(JSON, default=dict)
    gate_failed: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    gate_reason: Mapped[str] = mapped_column(Text, default="")
    error: Mapped[str] = mapped_column(Text, default="")
    project: Mapped[Project] = relationship(back_populates="scans")
    findings: Mapped[list["FindingRow"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    files: Mapped[list["ScanFile"]] = relationship(cascade="all, delete-orphan")


class FindingRow(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    rule_id: Mapped[str] = mapped_column(String(60), index=True)
    title: Mapped[str] = mapped_column(String(200))
    message: Mapped[str] = mapped_column(Text)
    file: Mapped[str] = mapped_column(String(500), index=True)
    line: Mapped[int] = mapped_column(Integer)
    end_line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    severity: Mapped[str] = mapped_column(String(10), index=True)
    confidence: Mapped[str] = mapped_column(String(10))
    cwe: Mapped[str] = mapped_column(String(20), default="")
    owasp: Mapped[str] = mapped_column(String(80), default="")
    snippet: Mapped[str] = mapped_column(Text, default="")
    engine: Mapped[str] = mapped_column(String(60), default="")
    language: Mapped[str] = mapped_column(String(20), default="python")
    trace: Mapped[list] = mapped_column(JSON, default=list)
    remediation: Mapped[str] = mapped_column(Text, default="")
    risk_score: Mapped[float] = mapped_column(Float, default=0)
    status: Mapped[str] = mapped_column(String(20), default="open")  # open|false_positive|accepted_risk|fixed
    ai: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    ai_status: Mapped[str] = mapped_column(String(20), default="none")  # none|pending|done|failed
    scan: Mapped[Scan] = relationship(back_populates="findings")


class ScanFile(Base):
    """Conteúdo dos arquivos com achados (contexto para a IA e visualização no dashboard)."""
    __tablename__ = "scan_files"
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    path: Mapped[str] = mapped_column(String(500))
    content: Mapped[str] = mapped_column(Text)


_connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, pool_pre_ping=True, connect_args=_connect_args)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


def init_db() -> None:
    Base.metadata.create_all(engine)


def get_session() -> Iterator:
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
