# VulnTrack

VulnTrack is an open, organization-neutral, multi-tenant vulnerability registry and remediation API. This repository is an **initial backend foundation**, not yet a production-ready vulnerability management system.

## Features implemented

- Canonical vulnerability and CVE/GHSA/OSV identifier registry
- Tenant-scoped assets, independent remediation occurrences, assignment and status tracking
- Deduplicated source observations, context-aware occurrence correlation, and recurrence reopening
- CISA KEV JSON import, manual live sync, idempotent KEV updates without false asset findings
- Tenant RBAC and JWT verification against configurable OIDC issuer, JWKS and audience
- Dashboard APIs, ingestion job summaries, administrator audit log
- OpenAPI documentation at `/docs` and pytest coverage of core correlation scenarios

## Local development

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[test]'
export VULNTRACK_DEV_AUTH=true  # local testing ONLY; grants admin access
uvicorn app.main:app --reload
pytest -q
```

For Docker, run `VULNTRACK_DEV_AUTH=true docker compose up --build` for localhost-only evaluation. **Do not enable development authentication on any network-accessible environment.** The Docker setup expects real OIDC settings before production deployment and requires PostgreSQL credentials to be changed.

## OIDC and PIV-Proxy

Set `VULNTRACK_OIDC_ISSUER`, `VULNTRACK_OIDC_JWKS_URL`, and `VULNTRACK_OIDC_AUDIENCE` for a compliant provider, including a PIV-Proxy deployment exposing standard OIDC JWTs. Requests require `Authorization: Bearer <access-token>` with issuer, audience, signature and expiration verification. A `roles` claim including `vulntrack-admin` grants global administration. Other users must be added to tenants by a global admin (`POST /api/tenants/{id}/members`). Verify your provider's actual claim mapping. TLS termination and interactive OIDC browser login must be configured separately.

## Example

Create a tenant:
```bash
curl -X POST http://localhost:8000/api/tenants -H 'Content-Type: application/json' -d '{"name":"Engineering"}'
```
Use its returned `id` to ingest scanner findings:
```json
{"findings":[{"tenant_id":"TENANT_ID","source":"snyk","source_id":"snyk-1","identifiers":["CVE-2026-12345"],"asset_kind":"repository","asset_external_id":"github:org/repo","asset_name":"org/repo","context":"example-package@1.2","title":"Example vulnerability","severity":"high"}]}
```
POST this object to `/api/ingest`. The response contains job and processed count. `GET /api/occurrences`, `GET /api/dashboard`, and `PATCH /api/occurrences/{id}` support tenant remediation workflows.

## Security boundaries and next phases

This is **not** a full Snyk/Qualys integration or all-format importer. It currently accepts a common normalized JSON finding payload; automated connector sync, SARIF, CSAF, CycloneDX, SPDX, OSV parsing, Qualys QID multi-CVE handling, scanner credentials, scheduling, persistent workers, exception/triage workflows, merge/split controls, ingestion concurrency handling, migrations, browser dashboards and PIV-Proxy UI login are **not yet implemented**. Unknown or ambiguous identifiers are rejected for triage instead of silently merged. CISA KEV does not imply asset exposure. This backend should not be deployed for sensitive operational data without further authentication hardening, secure secrets management, migrations, tenant isolation testing, pagination and production security review.
