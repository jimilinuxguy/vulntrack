"""Strict identifier-based, non-destructive finding correlation."""
import re
from sqlalchemy import select
from sqlalchemy.orm import Session
from .models import Vulnerability, Identifier, Asset, Occurrence, Observation, now

CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)

def normalize_identifier(identifier: str) -> tuple[str, str]:
    val = identifier.strip().upper()
    if CVE.fullmatch(val): return "CVE", val
    if re.fullmatch(r"GHSA-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}", val): return "GHSA", val
    if re.fullmatch(r"OSV-[A-Z0-9._-]+", val): return "OSV", val
    raise ValueError(f"Unsupported authoritative identifier: {identifier}")

def get_vulnerability(db: Session, identifiers: list[str], title: str, severity: str="unknown") -> Vulnerability:
    keys = list(dict.fromkeys(normalize_identifier(i) for i in identifiers))
    if not keys: raise ValueError("A verified CVE, GHSA or OSV identifier is required; unverified findings need manual triage")
    matches = {x.vulnerability_id for ns,val in keys for x in db.scalars(select(Identifier).where(Identifier.namespace == ns, Identifier.value == val))}
    if len(matches) > 1: raise ValueError("Identifiers resolve to conflicting vulnerabilities; manual correlation required")
    if matches:
        vuln = db.get(Vulnerability, next(iter(matches)))
    else:
        vuln = Vulnerability(title=title[:500], severity=severity)
        db.add(vuln)
        db.flush()
    for ns,val in keys:
        if not db.scalar(select(Identifier.id).where(Identifier.namespace == ns, Identifier.value == val)):
            db.add(Identifier(vulnerability_id=vuln.id,namespace=ns,value=val))
    db.flush()
    return vuln

def ingest_finding(db: Session, *, tenant_id: str, source: str, source_id: str, identifiers: list[str], asset_kind: str, asset_external_id: str, asset_name: str, context: str="", title: str="", severity: str="unknown", evidence: dict | None=None) -> Occurrence:
    if not tenant_id or not asset_external_id or not source_id or not source: raise ValueError("Tenant, stable asset ID, source, and source finding ID are required")
    vuln = get_vulnerability(db, identifiers, title or identifiers[0], severity)
    asset = db.scalar(select(Asset).where(Asset.tenant_id == tenant_id, Asset.kind == asset_kind, Asset.external_id == asset_external_id))
    if not asset:
        asset = Asset(tenant_id=tenant_id, kind=asset_kind, external_id=asset_external_id, name=asset_name[:300]); db.add(asset); db.flush()
    occurrence = db.scalar(select(Occurrence).where(Occurrence.vulnerability_id == vuln.id, Occurrence.asset_id == asset.id, Occurrence.context == context))
    if not occurrence:
        occurrence = Occurrence(vulnerability_id=vuln.id, asset_id=asset.id, context=context); db.add(occurrence); db.flush()
    else:
        occurrence.last_seen = now()
        if occurrence.status == "remediated": occurrence.status = "reopened"
    observation = db.scalar(select(Observation).where(Observation.source == source, Observation.source_finding_id == source_id, Observation.asset_id == asset.id, Observation.context == context))
    if observation and observation.occurrence_id != occurrence.id: raise ValueError("Source observation identity conflicts with previous correlation")
    if observation:
        observation.last_seen = now(); observation.evidence = evidence or {}
    else:
        db.add(Observation(occurrence_id=occurrence.id, asset_id=asset.id, context=context, source=source, source_finding_id=source_id, evidence=evidence or {}))
    db.flush()
    return occurrence

def import_kev(db: Session, catalog: dict) -> int:
    entries = catalog.get("vulnerabilities")
    if not isinstance(entries,list): raise ValueError("CISA KEV JSON must contain vulnerabilities array")
    count=0
    for entry in entries:
        cve=entry.get("cveID", "")
        if not CVE.fullmatch(cve): raise ValueError("Invalid KEV CVE identifier")
        vuln=get_vulnerability(db,[cve], entry.get("vulnerabilityName",cve),"unknown")
        vuln.is_kev=True
        vuln.kev_metadata={key:entry.get(key) for key in ("dateAdded","dueDate","knownRansomwareCampaignUse","requiredAction","notes","vendorProject","product")}
        count+=1
    db.flush()
    return count
