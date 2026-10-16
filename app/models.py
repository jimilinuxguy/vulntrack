from datetime import datetime, timezone
from uuid import uuid4
from sqlalchemy import String, Integer, DateTime, ForeignKey, UniqueConstraint, Text, JSON, Boolean
from sqlalchemy.orm import Mapped, mapped_column
from .db import Base

def new_id(): return str(uuid4())
def now(): return datetime.now(timezone.utc)

class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(200), unique=True)

class Membership(Base):
    __tablename__ = "memberships"
    __table_args__ = (UniqueConstraint("subject", "tenant_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    subject: Mapped[str] = mapped_column(String(300), index=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"))
    role: Mapped[str] = mapped_column(String(20), default="viewer")

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    title: Mapped[str] = mapped_column(String(500))
    severity: Mapped[str] = mapped_column(String(32), default="unknown")
    description: Mapped[str] = mapped_column(Text, default="")
    is_kev: Mapped[bool] = mapped_column(Boolean, default=False)
    kev_metadata: Mapped[dict] = mapped_column(JSON, default=dict)

class Identifier(Base):
    __tablename__ = "identifiers"
    __table_args__ = (UniqueConstraint("namespace", "value"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    vulnerability_id: Mapped[str] = mapped_column(ForeignKey("vulnerabilities.id"), index=True)
    namespace: Mapped[str] = mapped_column(String(30))
    value: Mapped[str] = mapped_column(String(250))

class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("tenant_id", "kind", "external_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    kind: Mapped[str] = mapped_column(String(40))
    external_id: Mapped[str] = mapped_column(String(700))
    name: Mapped[str] = mapped_column(String(300))

class Occurrence(Base):
    __tablename__ = "occurrences"
    __table_args__ = (UniqueConstraint("vulnerability_id", "asset_id", "context"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    vulnerability_id: Mapped[str] = mapped_column(ForeignKey("vulnerabilities.id"), index=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), index=True)
    context: Mapped[str] = mapped_column(String(500), default="")
    status: Mapped[str] = mapped_column(String(30), default="open")
    assignee: Mapped[str] = mapped_column(String(300), default="")
    due_date: Mapped[str] = mapped_column(String(30), default="")
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class Observation(Base):
    __tablename__ = "observations"
    __table_args__ = (UniqueConstraint("source", "source_finding_id", "asset_id", "context"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    occurrence_id: Mapped[str] = mapped_column(ForeignKey("occurrences.id"), index=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"))
    context: Mapped[str] = mapped_column(String(500), default="")
    source: Mapped[str] = mapped_column(String(50))
    source_finding_id: Mapped[str] = mapped_column(String(300))
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class ImportJob(Base):
    __tablename__ = "import_jobs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    source: Mapped[str] = mapped_column(String(50))
    status: Mapped[str] = mapped_column(String(30), default="running")
    imported: Mapped[int] = mapped_column(Integer, default=0)
    errors: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    actor: Mapped[str] = mapped_column(String(300))
    action: Mapped[str] = mapped_column(String(120))
    object_id: Mapped[str] = mapped_column(String(100))
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
