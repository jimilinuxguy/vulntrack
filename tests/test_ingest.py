import pytest
from sqlalchemy import create_engine,select,func
from sqlalchemy.orm import Session
from app.db import Base
from app.models import Tenant,Vulnerability,Occurrence,Observation,Identifier
from app.ingest import ingest_finding,import_kev

@pytest.fixture
def db():
    engine=create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        session.add_all([Tenant(id="one",name="One"),Tenant(id="two",name="Two")]);session.commit()
        yield session
    engine.dispose()

def sample(tenant="one",source="snyk",asset="repo-a",source_id="finding-1",context="pkg@1"):
    return dict(tenant_id=tenant,source=source,source_id=source_id,identifiers=["CVE-2026-12345"],asset_kind="repository",asset_external_id=asset,asset_name=asset,context=context,title="Test")

def count(db,model): return db.scalar(select(func.count()).select_from(model))

def test_dedupes_scanners_without_merging_tenants(db):
    ingest_finding(db,**sample())
    ingest_finding(db,**sample(source="qualys",source_id="qid-2"))
    ingest_finding(db,**sample(tenant="two"))
    ingest_finding(db,**sample())
    assert count(db,Vulnerability)==1
    assert count(db,Occurrence)==2
    assert count(db,Observation)==3

def test_distinct_component_context(db):
    ingest_finding(db,**sample())
    ingest_finding(db,**sample(source_id="finding-2",context="another-package"))
    assert count(db,Occurrence)==2

def test_kev_is_idempotent_and_does_not_create_occurrences(db):
    payload={"vulnerabilities":[{"cveID":"CVE-2026-12345","vulnerabilityName":"Exploit","dateAdded":"2026-10-01"}]}
    import_kev(db,payload);import_kev(db,payload)
    assert count(db,Vulnerability)==1
    assert count(db,Identifier)==1
    assert count(db,Occurrence)==0
    assert db.scalar(select(Vulnerability)).is_kev

def test_reopens_existing_occurrence(db):
    occurrence=ingest_finding(db,**sample());occurrence.status="remediated";db.flush()
    again=ingest_finding(db,**sample())
    assert again.id==occurrence.id and again.status=="reopened"

def test_no_unsupported_identity_guessing(db):
    with pytest.raises(ValueError):
        ingest_finding(db,**{**sample(),"identifiers":["scanner-title-only"]})
    assert count(db,Vulnerability)==0

def test_conflicting_aliases_not_merged(db):
    ingest_finding(db,**sample())
    ingest_finding(db,**{**sample(asset="repo-b",source_id="other"),"identifiers":["CVE-2026-99999"]})
    with pytest.raises(ValueError,match="conflicting"):
        ingest_finding(db,**{**sample(asset="repo-c",source_id="third"),"identifiers":["CVE-2026-12345","CVE-2026-99999"]})
