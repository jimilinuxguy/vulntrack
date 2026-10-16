# VulnTrack web portal milestone

## Included

The browser portal is served at `/` from the same FastAPI origin as the API. It provides:

- Responsive dark-mode security operations overview with tenant-scoped metrics and a recent queue
- Tenant selector, search/filter remediation punch list, status/owner/due-date editor
- Finding details with scanner provenance and persistent remediation notes
- Canonical vulnerability registry
- Admin forms for tenant provisioning, membership management, CISA KEV synchronization and normalized JSON batch import
- OIDC authorization-code login with PKCE, state checking, and bearer-token API calls

## Local preview

```sh
VULNTRACK_DEV_AUTH=true docker compose up --build
```

Visit http://localhost:8000/. Development mode grants global administrator privileges and must never be exposed outside localhost.

## OIDC / PIV-Proxy integration

The portal uses the public OIDC authorization code + PKCE flow. Configure the following environment variables on the API container:

```sh
VULNTRACK_DEV_AUTH=false
VULNTRACK_OIDC_ISSUER=https://idp.example.gov
VULNTRACK_OIDC_JWKS_URL=https://idp.example.gov/.well-known/jwks.json
VULNTRACK_OIDC_AUDIENCE=vulntrack
VULNTRACK_OIDC_CLIENT_ID=vulntrack-web
VULNTRACK_OIDC_AUTHORIZE_URL=https://idp.example.gov/authorize
VULNTRACK_OIDC_TOKEN_URL=https://idp.example.gov/token
VULNTRACK_OIDC_SCOPE="openid profile"
```

The identity provider must register `https://YOUR-VULNTRACK-ORIGIN/` as an exact redirect URI, permit public-client authorization code + PKCE, and allow browser-origin CORS for the token endpoint. It must issue a **JWT access token** whose audience matches `VULNTRACK_OIDC_AUDIENCE`. The API verifies JWT signature, issuer, audience, and expiry. The configured issuer and endpoints must belong to the same trusted provider. PIV-Proxy is compatible only when configured to expose these standards-based endpoints and access-token claims. An ID token must not be substituted for an API access token.

Tokens are stored in per-tab session storage for this prototype. Production deployments should move to a hardened backend-for-frontend with HttpOnly secure SameSite cookies, CSRF protection, token refresh/revocation and IdP end-session logout. Current Sign out removes the local token only. Configure HTTPS, CSP, strict CORS and hardened authentication before processing sensitive findings.

The global admin role is mapped from `roles` containing `vulntrack-admin`. Tenant roles are managed in VulnTrack. Tenant membership is enforced by API, including note access. The UI cannot grant permissions on its own.

## Current constraints / future work

- No scanner-native Snyk or Qualys connectors or scheduled jobs yet
- No SARIF, CycloneDX, SPDX, CSAF, OSV or Qualys multi-CVE import adapters yet
- No evidence display or attachment upload; evidence remains in protected database records
- No database migration framework, optimistic locking, bulk assignment, alerts or SLA policies
- No risk acceptance approval workflow, asset-mapping triage, correlation review/merge/split, or analytics history
- No pagination beyond existing API limits
- No production-ready IdP single logout, session rotation, or refresh tokens

This milestone is a reviewable portal POC, not a production authorization.
