"""Browser portal endpoints. Authorization is enforced server-side, never by UI visibility."""
import os
from datetime import datetime, timezone
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
import httpx
from urllib.parse import urlsplit, parse_qs
from pydantic import BaseModel, Field
from sqlalchemy import ForeignKey, String, Text, DateTime, select
from sqlalchemy.orm import Mapped, mapped_column, Session
from .db import Base, session
from .models import Occurrence, Asset, Vulnerability, Observation, AuditEvent, Tenant, Identifier, new_id
from .auth import Principal, principal
from .main import require_tenant, audit, visible_tenants

router = APIRouter()

class Note(Base):
    __tablename__ = "remediation_notes"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    occurrence_id: Mapped[str] = mapped_column(ForeignKey("occurrences.id"), index=True)
    author: Mapped[str] = mapped_column(String(300))
    text: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class NoteInput(BaseModel):
    text: str = Field(min_length=1, max_length=4000)


@router.post("/api/auth/token")
async def oidc_token(request: Request):
    endpoint = os.getenv("VULNTRACK_OIDC_TOKEN_URL", "")
    client_id = os.getenv("VULNTRACK_OIDC_CLIENT_ID", "")
    if not endpoint or urlsplit(endpoint).scheme != "https" or not client_id:
        raise HTTPException(503, "OIDC provider unavailable")
    if request.headers.get("content-type", "").split(";")[0].strip() != "application/x-www-form-urlencoded":
        raise HTTPException(415, "Form encoding required")
    raw = await request.body()
    if len(raw) > 4096:
        raise HTTPException(413, "Request too large")
    try:
        form = parse_qs(raw.decode("utf-8"), keep_blank_values=True)
    except UnicodeDecodeError:
        raise HTTPException(400, "Invalid form")
    required = {"grant_type", "code", "client_id", "redirect_uri", "code_verifier"}
    if set(form) != required or any(len(v) != 1 for v in form.values()):
        raise HTTPException(400, "Invalid OIDC parameters")
    if form["grant_type"][0] != "authorization_code" or form["client_id"][0] != client_id:
        raise HTTPException(400, "OIDC client mismatch")
    if form["redirect_uri"][0] != "https://" + request.url.hostname + "/":
        raise HTTPException(400, "OIDC redirect mismatch")
    try:
        async with httpx.AsyncClient(timeout=8, follow_redirects=False) as client:
            response = await client.post(endpoint, data={k: v[0] for k, v in form.items()})
    except httpx.HTTPError as exc:
        raise HTTPException(502, "OIDC token service unavailable") from exc
    if response.status_code != 200:
        raise HTTPException(401, "OIDC exchange rejected")
    tokens = response.json()
    if not isinstance(tokens, dict) or not isinstance(tokens.get("id_token"), str):
        raise HTTPException(502, "OIDC response invalid")
    return JSONResponse({"id_token": tokens["id_token"]}, headers={"Cache-Control": "no-store"})

@router.get("/api/auth/config")
def auth_config():
    # Only public client metadata; secrets must never be placed here.
    return {
        "issuer": os.getenv("VULNTRACK_OIDC_ISSUER", ""),
        "client_id": os.getenv("VULNTRACK_OIDC_CLIENT_ID", ""),
        "authorize_url": os.getenv("VULNTRACK_OIDC_AUTHORIZE_URL", ""),
        "token_url": os.getenv("VULNTRACK_OIDC_TOKEN_URL", ""),
        "scope": os.getenv("VULNTRACK_OIDC_SCOPE", "openid profile"),
        "dev_auth": os.getenv("VULNTRACK_DEV_AUTH", "").lower() == "true" and not os.getenv("VULNTRACK_OIDC_ISSUER"),
    }

@router.get("/api/occurrences/{occurrence_id}/detail")
def occurrence_detail(occurrence_id: str, db: Session = Depends(session), user: Principal = Depends(principal)):
    row = db.execute(select(Occurrence, Asset, Vulnerability).join(Asset, Occurrence.asset_id == Asset.id).join(Vulnerability, Occurrence.vulnerability_id == Vulnerability.id).where(Occurrence.id == occurrence_id)).first()
    if row is None: raise HTTPException(404, "Occurrence not found")
    occurrence, asset, vuln = row
    require_tenant(db, user, asset.tenant_id)
    observations = db.scalars(select(Observation).where(Observation.occurrence_id == occurrence_id)).all()
    return {
        "id": occurrence.id, "tenant_id": asset.tenant_id,
        "asset": {"name": asset.name, "kind": asset.kind, "external_id": asset.external_id},
        "vulnerability": {"id": vuln.id, "title": vuln.title, "description": vuln.description, "severity": vuln.severity, "is_kev": vuln.is_kev, "kev_metadata": vuln.kev_metadata},
        "context": occurrence.context, "status": occurrence.status, "assignee": occurrence.assignee,
        "due_date": occurrence.due_date, "first_seen": occurrence.first_seen, "last_seen": occurrence.last_seen,
        "observations": [{"source": o.source, "source_finding_id": o.source_finding_id, "last_seen": o.last_seen} for o in observations],
        "notes": [{"id": n.id, "author": n.author, "text": n.text, "created_at": n.created_at} for n in db.scalars(select(Note).where(Note.occurrence_id == occurrence_id).order_by(Note.created_at.desc()))]
    }

@router.post("/api/occurrences/{occurrence_id}/notes", status_code=201)
def add_note(occurrence_id: str, body: NoteInput, db: Session = Depends(session), user: Principal = Depends(principal)):
    row = db.execute(select(Occurrence, Asset).join(Asset, Occurrence.asset_id == Asset.id).where(Occurrence.id == occurrence_id)).first()
    if row is None: raise HTTPException(404, "Occurrence not found")
    require_tenant(db, user, row[1].tenant_id, write=True)
    note = Note(occurrence_id=occurrence_id, author=user.subject, text=body.text.strip())
    if not note.text: raise HTTPException(422, "Note cannot be empty")
    db.add(note); db.flush()
    audit(db, user, "occurrence.note_added", occurrence_id, {"note_id": note.id})
    db.commit()
    return {"id": note.id, "author": note.author, "text": note.text}

@router.get("/")
def index():
    return FileResponse(Path(__file__).parent / "static" / "index.html")

@router.get("/api/vulnerabilities/{vulnerability_id}/impact")
def vulnerability_impact(vulnerability_id: str, tenant_id: str | None = None, db: Session = Depends(session), user: Principal = Depends(principal)):
    """Show one canonical vulnerability and its occurrences within authorized tenants."""
    vuln = db.get(Vulnerability, vulnerability_id)
    if vuln is None:
        raise HTTPException(404, "Vulnerability not found")
    allowed = visible_tenants(db, user)
    if tenant_id:
        require_tenant(db, user, tenant_id)
        allowed = {tenant_id}
    rows = db.execute(
        select(Occurrence, Asset, Tenant)
        .join(Asset, Occurrence.asset_id == Asset.id)
        .join(Tenant, Asset.tenant_id == Tenant.id)
        .where(Occurrence.vulnerability_id == vulnerability_id, Asset.tenant_id.in_(allowed))
        .order_by(Tenant.name, Asset.name)
    ).all()
    if not rows and not user.admin:
        raise HTTPException(404, "Vulnerability not found")
    tenants = {}
    for occurrence, asset, tenant in rows:
        item = tenants.setdefault(tenant.id, {"id": tenant.id, "name": tenant.name, "total": 0, "by_status": {}, "assets": []})
        item["total"] += 1
        item["by_status"][occurrence.status] = item["by_status"].get(occurrence.status, 0) + 1
        item["assets"].append({
            "occurrence_id": occurrence.id, "name": asset.name, "kind": asset.kind,
            "external_id": asset.external_id, "context": occurrence.context,
            "status": occurrence.status, "assignee": occurrence.assignee, "due_date": occurrence.due_date,
        })
    identifiers = [f"{i.namespace}:{i.value}" for i in db.scalars(select(Identifier).where(Identifier.vulnerability_id == vulnerability_id))]
    return {
        "id": vuln.id, "title": vuln.title, "severity": vuln.severity,
        "is_kev": vuln.is_kev, "kev_metadata": vuln.kev_metadata or {},
        "identifiers": identifiers, "tenant_count": len(tenants),
        "total_occurrences": len(rows), "tenants": list(tenants.values()),
    }
