# Demo seed data

The demo seed script populates the existing database with five fictional tenants, 12 canonical CVEs, roughly 48 independently tracked remediation occurrences, five simulated KEV records, overlapping scanner observations, multiple statuses, assigned owners and due dates. The CVE identifiers refer to real vulnerabilities, but **all affected assets, tenant relationships, scanner observations and remediation states are invented**. No external scanner or CISA network calls are made.

Run with the local development stack:

```bash
VULNTRACK_DEV_AUTH=true docker compose up -d --build
VULNTRACK_DEV_AUTH=true docker compose exec -e VULNTRACK_DEV_AUTH=true api python -m app.seed_demo --confirm-demo
```

Visit http://localhost:8000/ and refresh. Select a tenant to compare remediation views, inspect overlapping observations, and update assignments. For local Python use, set `VULNTRACK_DEV_AUTH=true` and run `python -m app.seed_demo --confirm-demo`.

**Safety:** This writes into the configured database. Use only a disposable development database, never production. Seeding is repeatable and does not create duplicate findings. Existing matching observations are refreshed, so avoid re-seeding after you begin manually verifying remediation. The script does not erase data and it does not provide a reset option. For a clean demo, reset your disposable database volume first.

Fictional tenant subjects are `demo-1-manager`, `demo-1-analyst`, `demo-1-viewer`, through `demo-5-*`. Development mode signs in as global admin; testing those roles requires an identity provider or API tests with matching subject claims.
