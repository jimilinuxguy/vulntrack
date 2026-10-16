from typing import Any
from fastapi import FastAPI, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, func
from sqlalchemy.orm import Session
import httpx
from .db import Base, engine, session
from .models import Tenant, Membership, Vulnerability, Identifier, Asset, Occurrence, Observation, ImportJob, AuditEvent
from .auth import Principal, principal, admin
from .ingest import ingest_finding, import_kev
from .settings import settings

app = FastAPI(title="VulnTrack", version="0.1.0", description="Multi-tenant vulnerability correlation and remediation")

@app.on_event("startup")
def init_db():
    Base.metadata.create_all(bind=engine)

class TenantCreate(BaseModel):
    name: str = Field(min_length=1,max_length=200)

class MemberCreate(BaseModel):
    subject: str
    role: str = "viewer"

class FindingInput(BaseModel):
    tenant_id: str
    source: str
    source_id: str
    identifiers: list[str]
    asset_kind: str
    asset_external_id: str
    asset_name: str
    context: str = ""
    title: str = ""
    severity: str = "unknown"
    evidence: dict[str,Any] = Field(default_factory=dict)

class BatchInput(BaseModel):
    findings: list[FindingInput] = Field(max_length=1000)

class AssignmentUpdate(BaseModel):
    status: str | None = None
    assignee: str | None = None
    due_date: str | None = None

class KevPayload(BaseModel):
    vulnerabilities: list[dict[str,Any]]

VALID_ROLES = {"viewer", "analyst", "manager"}
VALID_STATUSES = {"open", "in_progress", "risk_accepted", "remediated", "reopened", "false_positive"}

def visible_tenants(db: Session, user: Principal) -> set[str]:
    if user.admin: return set(db.scalars(select(Tenant.id)))
    return set(db.scalars(select(Membership.tenant_id).where(Membership.subject == user.subject)))

def require_tenant(db: Session, user: Principal, tenant_id: str, write: bool = False):
    if user.admin: return
    member = db.scalar(select(Membership).where(Membership.subject == user.subject, Membership.tenant_id == tenant_id))
    if not member: raise HTTPException(403, "Tenant access denied")
    if write and member.role not in ("analyst", "manager"): raise HTTPException(403, "Tenant write access denied")

def audit(db: Session, user: Principal, action: str, object_id: str, details: dict | None = None):
    db.add(AuditEvent(actor=user.subject, action=action, object_id=object_id, details=details or {}))

@app.get("/health")
def health(): return {"status":"ok"}

@app.get("/api/me")
def me(db: Session=Depends(session), user: Principal=Depends(principal)):
    return {"subject":user.subject,"admin":user.admin,"tenant_ids":sorted(visible_tenants(db,user))}

@app.get("/api/tenants")
def tenants(db: Session=Depends(session), user: Principal=Depends(principal)):
    ids=visible_tenants(db,user)
    return [{"id":t.id,"name":t.name} for t in db.scalars(select(Tenant).where(Tenant.id.in_(ids)).order_by(Tenant.name))]

@app.post("/api/tenants", status_code=201)
def create_tenant(body:TenantCreate, db:Session=Depends(session), user:Principal=Depends(admin)):
    if db.scalar(select(Tenant.id).where(Tenant.name == body.name)): raise HTTPException(409,"Tenant already exists")
    t=Tenant(name=body.name);db.add(t);db.flush();audit(db,user,"tenant.created",t.id);db.commit()
    return {"id":t.id,"name":t.name}

@app.post("/api/tenants/{tenant_id}/members",status_code=201)
def add_member(tenant_id:str,body:MemberCreate,db:Session=Depends(session),user:Principal=Depends(admin)):
    if not db.get(Tenant,tenant_id): raise HTTPException(404,"Tenant not found")
    if body.role not in VALID_ROLES: raise HTTPException(422,"Invalid role")
    m=db.scalar(select(Membership).where(Membership.tenant_id==tenant_id,Membership.subject==body.subject))
    if m: m.role=body.role
    else: m=Membership(tenant_id=tenant_id,subject=body.subject,role=body.role);db.add(m)
    audit(db,user,"membership.updated",tenant_id,{"subject":body.subject,"role":body.role});db.commit()
    return {"subject":body.subject,"role":body.role}

@app.get("/api/vulnerabilities")
def vulnerabilities(db:Session=Depends(session),user:Principal=Depends(principal),limit:int=Query(default=100,ge=1,le=500)):
    ids=visible_tenants(db,user)
    stmt=select(Vulnerability).join(Occurrence,Occurrence.vulnerability_id==Vulnerability.id).join(Asset,Asset.id==Occurrence.asset_id).where(Asset.tenant_id.in_(ids)).distinct().limit(limit)
    if user.admin: stmt=select(Vulnerability).limit(limit)
    return [{"id":v.id,"title":v.title,"severity":v.severity,"is_kev":v.is_kev,"identifiers":[f"{i.namespace}:{i.value}" for i in db.scalars(select(Identifier).where(Identifier.vulnerability_id==v.id))]} for v in db.scalars(stmt)]

@app.get("/api/occurrences")
def occurrences(tenant_id:str|None=None,db:Session=Depends(session),user:Principal=Depends(principal)):
    ids=visible_tenants(db,user)
    if tenant_id:
        require_tenant(db,user,tenant_id)
        ids={tenant_id}
    stmt=select(Occurrence,Asset,Vulnerability).join(Asset,Occurrence.asset_id==Asset.id).join(Vulnerability,Occurrence.vulnerability_id==Vulnerability.id).where(Asset.tenant_id.in_(ids)).order_by(Occurrence.last_seen.desc()).limit(500)
    return [{"id":o.id,"tenant_id":a.tenant_id,"asset":a.name,"asset_kind":a.kind,"asset_external_id":a.external_id,"vulnerability_id":v.id,"title":v.title,"severity":v.severity,"is_kev":v.is_kev,"context":o.context,"status":o.status,"assignee":o.assignee,"due_date":o.due_date} for o,a,v in db.execute(stmt)]

@app.get("/api/dashboard")
def dashboard(tenant_id:str|None=None,db:Session=Depends(session),user:Principal=Depends(principal)):
    ids=visible_tenants(db,user)
    if tenant_id: require_tenant(db,user,tenant_id);ids={tenant_id}
    stmt=select(Occurrence.status,func.count()).join(Asset).where(Asset.tenant_id.in_(ids)).group_by(Occurrence.status)
    counts=dict(db.execute(stmt).all())
    kev=db.scalar(select(func.count()).select_from(Occurrence).join(Asset).join(Vulnerability).where(Asset.tenant_id.in_(ids),Vulnerability.is_kev.is_(True))) or 0
    return {"by_status":counts,"kev_occurrences":kev,"total":sum(counts.values())}

@app.patch("/api/occurrences/{occurrence_id}")
def assign(occurrence_id:str,body:AssignmentUpdate,db:Session=Depends(session),user:Principal=Depends(principal)):
    row=db.execute(select(Occurrence,Asset).join(Asset).where(Occurrence.id==occurrence_id)).first()
    if not row: raise HTTPException(404,"Occurrence not found")
    o,a=row;require_tenant(db,user,a.tenant_id,write=True)
    changes=body.model_dump(exclude_unset=True)
    if "status" in changes and changes["status"] not in VALID_STATUSES: raise HTTPException(422,"Invalid status")
    for key,value in changes.items(): setattr(o,key,value or "")
    audit(db,user,"occurrence.updated",o.id,{"fields":list(changes)});db.commit()
    return {"id":o.id,"status":o.status,"assignee":o.assignee,"due_date":o.due_date}

@app.post("/api/ingest",status_code=202)
def ingest(body:BatchInput,db:Session=Depends(session),user:Principal=Depends(principal)):
    # Validate all tenant permissions before writing anything.
    for finding in body.findings: require_tenant(db,user,finding.tenant_id,write=True)
    job=ImportJob(source="batch",status="running");db.add(job);db.flush()
    try:
        for item in body.findings:
            ingest_finding(db,**item.model_dump());job.imported+=1
        job.status="complete";audit(db,user,"ingest.completed",job.id,{"count":job.imported});db.commit()
    except (ValueError,TypeError) as exc:
        db.rollback();raise HTTPException(422,str(exc)) from exc
    return {"job_id":job.id,"imported":job.imported}

@app.post("/api/admin/kev/import")
def kev_upload(body:KevPayload,db:Session=Depends(session),user:Principal=Depends(admin)):
    try:
        count=import_kev(db,body.model_dump());audit(db,user,"kev.imported","cisa",{"records":count});db.commit()
    except ValueError as exc: db.rollback();raise HTTPException(422,str(exc)) from exc
    return {"processed":count}

@app.post("/api/admin/kev/sync")
def kev_sync(db:Session=Depends(session),user:Principal=Depends(admin)):
    try:
        with httpx.Client(timeout=30,follow_redirects=False) as client:
            response=client.get(settings.kev_url);response.raise_for_status()
            if len(response.content)>20_000_000: raise ValueError("KEV feed exceeds size limit")
            catalog=response.json()
        count=import_kev(db,catalog);audit(db,user,"kev.synced","cisa",{"records":count});db.commit()
        return {"processed":count}
    except (httpx.HTTPError,ValueError) as exc:
        db.rollback();raise HTTPException(502,"KEV synchronization failed") from exc

@app.get("/api/admin/imports")
def imports(db:Session=Depends(session),user:Principal=Depends(admin)):
    return [{"id":x.id,"source":x.source,"status":x.status,"imported":x.imported} for x in db.scalars(select(ImportJob).order_by(ImportJob.created_at.desc()).limit(100))]

@app.get("/api/admin/audit")
def audit_events(db:Session=Depends(session),user:Principal=Depends(admin)):
    return [{"action":x.action,"actor":x.actor,"object_id":x.object_id,"created_at":x.created_at} for x in db.scalars(select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(100))]
