from sqlalchemy import create_engine, select, func
from sqlalchemy.orm import Session
from app.db import Base
from app.models import Tenant, Vulnerability, Occurrence, Observation, Membership
from app.seed_demo import seed, TENANTS

def test_seed_is_repeatable_and_preserves_remediation():
    engine=create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        first=seed(db)
        db.commit()
        assert first["tenants"]==5
        assert first["canonical_vulnerabilities"]==12
        assert first["occurrences"]>=40
        assert db.scalar(select(func.count()).select_from(Membership))==15
        observations=db.scalar(select(func.count()).select_from(Observation))
        occurrence=db.scalar(select(Occurrence).where(Occurrence.assignee!=""))
        occurrence.assignee="Reviewer changed owner"
        occurrence.status="in_progress"
        changed_id=occurrence.id
        db.commit()
        second=seed(db)
        db.commit()
        assert second["occurrences"]==first["occurrences"]
        assert db.scalar(select(func.count()).select_from(Observation))==observations
        assert db.get(Occurrence,changed_id).assignee=="Reviewer changed owner"
        assert db.get(Occurrence,changed_id).status=="in_progress"
        assert db.scalar(select(func.count()).select_from(Tenant))==len(TENANTS)
        assert db.scalar(select(func.count()).select_from(Vulnerability).where(Vulnerability.is_kev.is_(True)))==5
    engine.dispose()
