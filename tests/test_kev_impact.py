from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool
from app.db import Base, session
from app.auth import Principal, principal
from app.main import app
from app.models import Tenant, Membership, Vulnerability
from app.ingest import ingest_finding, import_kev

def test_kev_impact_isolation():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add_all([Tenant(id="t1", name="Tenant One"), Tenant(id="t2", name="Tenant Two")])
        db.add(Membership(subject="alice", tenant_id="t1", role="analyst"))
        db.flush()
        for tenant in ("t1", "t2"):
            ingest_finding(db, tenant_id=tenant, source="snyk", source_id=tenant,
                           identifiers=["CVE-2024-3400"], asset_kind="repo",
                           asset_external_id=tenant, asset_name="repo-" + tenant)
        import_kev(db, {"vulnerabilities": [{"cveID": "CVE-2024-3400", "vulnerabilityName": "Demo"}]})
        vuln_id = db.scalar(select(Vulnerability.id).where(Vulnerability.is_kev.is_(True)))
        db.commit()
    def override_db():
        with Session(engine) as db:
            yield db
    app.dependency_overrides[session] = override_db
    try:
        with TestClient(app) as client:
            app.dependency_overrides[principal] = lambda: Principal("alice", False)
            response = client.get(f"/api/vulnerabilities/{vuln_id}/impact")
            assert response.status_code == 200
            assert response.json()["tenant_count"] == 1
            assert response.json()["tenants"][0]["name"] == "Tenant One"
            assert client.get(f"/api/vulnerabilities/{vuln_id}/impact?tenant_id=t2").status_code == 403
            app.dependency_overrides[principal] = lambda: Principal("admin", True)
            response = client.get(f"/api/vulnerabilities/{vuln_id}/impact")
            assert response.status_code == 200
            assert response.json()["tenant_count"] == 2
            assert response.json()["total_occurrences"] == 2
    finally:
        app.dependency_overrides.clear()
        engine.dispose()
