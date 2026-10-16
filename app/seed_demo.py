"""Deterministic, repeatable demo data. Run only against a disposable database."""
import argparse
from datetime import date, timedelta
from sqlalchemy import select, func
from .db import Base, engine, SessionLocal
from .models import Tenant, Membership, Occurrence, Vulnerability, ImportJob
from .ingest import ingest_finding, import_kev

TENANTS = ["Platform Engineering", "Earth Observation", "Data Services", "Mission Operations", "Application Security"]
CVES = [
 ("CVE-2025-29927","Authentication bypass in middleware","critical","Snyk"),
 ("CVE-2024-3094","XZ Utils supply chain compromise","critical","Qualys"),
 ("CVE-2024-3400","PAN-OS command injection","critical","Qualys"),
 ("CVE-2023-34362","MOVEit Transfer SQL injection","critical","Qualys"),
 ("CVE-2024-6387","OpenSSH signal handler race condition","high","Qualys"),
 ("CVE-2023-38545","curl SOCKS5 heap buffer overflow","high","Snyk"),
 ("CVE-2024-21626","runc container breakout","high","Snyk"),
 ("CVE-2024-4577","PHP CGI argument injection","critical","Qualys"),
 ("CVE-2023-44487","HTTP/2 rapid reset denial of service","high","Snyk"),
 ("CVE-2024-1086","Linux kernel privilege escalation","high","Qualys"),
 ("CVE-2024-27198","TeamCity authentication bypass","critical","Snyk"),
 ("CVE-2024-23897","Jenkins CLI arbitrary file read","high","Snyk"),
]
KEVS = {"CVE-2024-3094": False, "CVE-2024-3400": True, "CVE-2023-34362": True, "CVE-2024-4577": True, "CVE-2024-1086": True}
STATUSES = ["open", "in_progress", "open", "remediated", "reopened", "risk_accepted", "false_positive"]
OWNERS = ["Alex Morgan", "Jordan Lee", "Taylor Kim", "Morgan Patel", "Riley Chen", ""]
ASSETS = [("repository","github:demo/portal-api","portal-api"),("repository","github:demo/data-pipeline","data-pipeline"),("aws","arn:aws:ec2:us-east-1:111122223333:instance/i-demo","web-prod-01"),("container","sha256:demo-container-image","worker-image")]

def seed(db):
    tenants = []
    for name in TENANTS:
        tenant = db.scalar(select(Tenant).where(Tenant.name == name))
        if tenant is None:
            tenant = Tenant(name=name)
            db.add(tenant)
            db.flush()
        tenants.append(tenant)
        for subject,role in [(f"demo-{TENANTS.index(name)+1}-manager","manager"),(f"demo-{TENANTS.index(name)+1}-analyst","analyst"),(f"demo-{TENANTS.index(name)+1}-viewer","viewer")]:
            if not db.scalar(select(Membership).where(Membership.tenant_id==tenant.id,Membership.subject==subject)):
                db.add(Membership(tenant_id=tenant.id,subject=subject,role=role))
    count=0
    for ti,tenant in enumerate(tenants):
        for vi,(cve,title,severity,source) in enumerate(CVES):
            if (ti+vi)%5==4: continue
            kind,external,name=ASSETS[(ti+vi)%len(ASSETS)]
            # Shared CVEs across tenants, two scanners for some identical occurrences.
            finding=dict(tenant_id=tenant.id,source=source.lower(),source_id=f"demo-{ti}-{vi}-{source.lower()}",identifiers=[cve],asset_kind=kind,asset_external_id=external,asset_name=name,context=f"component-{vi%4}@1.{vi}",title=title,severity=severity,evidence={"demo":True,"scanner":source})
            occurrence=ingest_finding(db,**finding)
            if vi%3==0:
                ingest_finding(db,**{**finding,"source":"internal","source_id":f"demo-{ti}-{vi}-internal"})
            # Re-seeding must not undo human edits to assignments.
            if not occurrence.assignee and occurrence.status=="open" and occurrence.due_date=="":
                occurrence.status=STATUSES[(ti*3+vi)%len(STATUSES)]
                occurrence.assignee=OWNERS[(ti+vi)%len(OWNERS)]
                occurrence.due_date=(date.today()+timedelta(days=(vi-5)*5)).isoformat()
            count+=1
    kev={"vulnerabilities":[{"cveID":cve,"vulnerabilityName":next(row[1] for row in CVES if row[0]==cve),"dateAdded":"2024-05-01","dueDate":"2024-05-22","knownRansomwareCampaignUse":"Known" if exploited else "Unknown","requiredAction":"Apply vendor mitigation"} for cve,exploited in KEVS.items()]}
    import_kev(db,kev)
    return {"tenants":len(tenants),"canonical_vulnerabilities":db.scalar(select(func.count()).select_from(Vulnerability)),"occurrences":db.scalar(select(func.count()).select_from(Occurrence)),"demo_findings_processed":count,"kev_records":len(KEVS)}

def main():
    parser=argparse.ArgumentParser(description="Populate a disposable VulnTrack database with fictional demo tenants and realistic sample CVEs.")
    parser.add_argument("--confirm-demo",action="store_true",help="Required safety acknowledgement")
    args=parser.parse_args()
    if not args.confirm_demo: parser.error("Pass --confirm-demo to seed a disposable local database.")
    from .settings import settings
    if not settings.dev_auth: parser.error("Demo seeding requires VULNTRACK_DEV_AUTH=true.")
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        try:
            result=seed(db)
            db.commit()
            print("Demo seed complete:",result)
            print("All tenant names, assets, scanner observations and assignments are fictional.")
        except Exception:
            db.rollback()
            raise

if __name__=="__main__": main()
