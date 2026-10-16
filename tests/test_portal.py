from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool
from app.db import Base, session
from app.auth import Principal, principal
from app.main import app
from app.models import Tenant, Membership
from app.ingest import ingest_finding

def test_portal_and_tenant_isolation():
    engine=create_engine("sqlite://",connect_args={"check_same_thread":False},poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add_all([Tenant(id="t1",name="One"),Tenant(id="t2",name="Two")])
        db.add(Membership(subject="alice",tenant_id="t1",role="analyst"))
        db.flush()
        first=ingest_finding(db,tenant_id="t1",source="snyk",source_id="a",identifiers=["CVE-2026-12345"],asset_kind="repo",asset_external_id="one",asset_name="One")
        second=ingest_finding(db,tenant_id="t2",source="qualys",source_id="b",identifiers=["CVE-2026-12345"],asset_kind="repo",asset_external_id="two",asset_name="Two")
        first_id,second_id=first.id,second.id
        db.commit()
    def db_override():
        with Session(engine) as db: yield db
    app.dependency_overrides[session]=db_override
    app.dependency_overrides[principal]=lambda:Principal("alice",False)
    try:
        with TestClient(app) as client:
            assert client.get("/").status_code==200
            assert client.get("/static/app.js").status_code==200
            assert client.get("/api/me").json()["tenant_ids"]==["t1"]
            rows=client.get("/api/occurrences").json()
            assert len(rows)==1 and rows[0]["id"]==first_id
            assert client.get("/api/occurrences/"+second_id+"/detail").status_code==403
            assert client.post("/api/occurrences/"+second_id+"/notes",json={"text":"Forbidden"}).status_code==403
            assert client.get("/api/occurrences/"+first_id+"/detail").status_code==200
            assert client.post("/api/occurrences/"+first_id+"/notes",json={"text":"Working on fix"}).status_code==201
            assert len(client.get("/api/occurrences/"+first_id+"/detail").json()["notes"])==1
            assert client.get("/api/admin/imports").status_code==403
    finally:
        app.dependency_overrides.clear()
        engine.dispose()
